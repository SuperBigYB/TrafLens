// SPDX-License-Identifier: Apache-2.0

package ckwriter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ch "github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type testColumnBlock struct {
	times  proto.ColDateTime
	values proto.ColUInt64
	resets int
}

func (b *testColumnBlock) ToInput(input proto.Input) proto.Input {
	return append(input, proto.InputColumn{Name: "time", Data: &b.times}, proto.InputColumn{Name: "value", Data: &b.values})
}
func (b *testColumnBlock) Reset() {
	b.resets++
	b.times.Reset()
	b.values.Reset()
}

type testItem struct {
	value    uint64
	released int
	block    *testColumnBlock
}

func (*testItem) OrgID() uint16                        { return 0 }
func (*testItem) NativeTagVersion() uint32             { return 1 }
func (i *testItem) NewColumnBlock() ckdb.CKColumnBlock { return i.block }
func (i *testItem) AppendToColumnBlock(block ckdb.CKColumnBlock) {
	if i.released != 0 {
		panic("using a released CKItem")
	}
	b := block.(*testColumnBlock)
	b.times.AppendRaw(proto.DateTime(i.value + 10))
	b.values.Append(i.value)
}
func (i *testItem) Release() { i.released++; i.value = ^uint64(0) }

func testWriter(t *testing.T) (*CKWriter, *QueueContext, *Cache, *testColumnBlock) {
	t.Helper()
	qc := &QueueContext{addrs: []string{"test:9000"}, conns: make([]writeConnection, 1), connCount: 1}
	block := new(testColumnBlock)
	cache := &Cache{queueContext: qc, prepare: "INSERT INTO test.samples VALUES", tableCreated: true}
	for _, value := range []uint64{11, 22} {
		item := &testItem{value: value, block: block}
		if err := cache.Add(item); err != nil || item.released != 1 {
			t.Fatalf("Add/release: %v, releases %d", err, item.released)
		}
	}
	writer := &CKWriter{addrs: qc.addrs, table: &ckdb.Table{Database: "test", LocalName: "samples"}, queueContexts: []*QueueContext{qc}}
	t.Cleanup(func() { qc.closeConn(0) })
	return writer, qc, cache, block
}

func assertFinalized(t *testing.T, cache *Cache, block *testColumnBlock) {
	t.Helper()
	if cache.size != 0 || block.resets != 1 || block.values.Rows() != 0 || cache.writeCounter != 1 || cache.lastWriteTime.IsZero() {
		t.Fatalf("cache not finalized once: size=%d resets=%d rows=%d round=%d time=%v", cache.size, block.resets, block.values.Rows(), cache.writeCounter, cache.lastWriteTime)
	}
}

type fakeConnection struct {
	do     func(context.Context, ch.Query) error
	closed int
}

func (c *fakeConnection) Do(ctx context.Context, q ch.Query) error { return c.do(ctx, q) }
func (c *fakeConnection) IsClosed() bool                           { return c.closed > 0 }
func (c *fakeConnection) Close() error                             { c.closed++; return nil }

// This peer exercises the real vendored ch-go transport over net.Pipe. It can
// fail after receiving only the query, or after accepting all row data but
// before acknowledging it. No external service, port, or driver patch is used.
type wireOutcome struct {
	values []uint64
	blocks int
	err    error
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func wireConnection(ctx context.Context, fault string) (writeConnection, <-chan wireOutcome, error) {
	client, server := net.Pipe()
	finished := make(chan wireOutcome, 1)
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		out := serveInsert(server, fault)
		finished <- out
	}()
	conn, err := ch.Dial(ctx, ch.Options{Dialer: pipeDialer{client}, ProtocolVersion: proto.Version, HandshakeTimeout: time.Second})
	if err != nil {
		client.Close()
		return nil, finished, err
	}
	return conn, finished, nil
}

func serveInsert(conn net.Conn, fault string) wireOutcome {
	out := wireOutcome{}
	r := proto.NewReader(conn)
	code, err := r.UVarInt()
	if err != nil || proto.ClientCode(code) != proto.ClientCodeHello {
		out.err = fmt.Errorf("client hello code %d: %v", code, err)
		return out
	}
	var hello proto.ClientHello
	if err := hello.Decode(r); err != nil {
		out.err = err
		return out
	}
	var b proto.Buffer
	serverHello := proto.ServerHello{Name: "test", Revision: proto.Version, Timezone: "UTC"}
	serverHello.EncodeAware(&b, hello.ProtocolVersion)
	if _, err := conn.Write(b.Buf); err != nil {
		out.err = err
		return out
	}
	b.Reset()
	if proto.FeatureAddendum.In(hello.ProtocolVersion) {
		if _, err := r.Str(); err != nil {
			out.err = err
			return out
		}
	}
	if fault == "stale-idle" {
		return out
	}
	code, err = r.UVarInt()
	if err != nil || proto.ClientCode(code) != proto.ClientCodeQuery {
		out.err = fmt.Errorf("query code %d: %v", code, err)
		return out
	}
	var query proto.Query
	if err := query.DecodeAware(r, proto.Version); err != nil {
		out.err = err
		return out
	}
	if query.Body != "INSERT INTO test.samples VALUES" {
		out.err = fmt.Errorf("unexpected query %s", query.Body)
		return out
	}
	if _, err := readClientBlock(r, nil); err != nil {
		out.err = err
		return out
	}
	if fault == "server-exception" {
		proto.ServerCodeException.Encode(&b)
		exception := proto.Exception{Code: proto.Error(60), Name: "UNKNOWN_TABLE", Message: "table does not exist"}
		exception.EncodeAware(&b, proto.Version)
		_, out.err = conn.Write(b.Buf)
		return out
	}
	if fault == "empty-eos" {
		proto.ServerCodeEndOfStream.Encode(&b)
		_, out.err = conn.Write(b.Buf)
		return out
	}
	if fault == "before-input" {
		return out
	}
	// ClickHouse sends a zero-row sample block before receiving INSERT data.
	proto.ServerCodeData.Encode(&b)
	proto.ClientData{}.EncodeAware(&b, proto.Version)
	var times proto.ColDateTime
	times.Location = time.UTC
	var values proto.ColUInt64
	sample := proto.Input{{Name: "time", Data: &times}, {Name: "value", Data: &values}}
	if err := (proto.Block{Columns: 2}).EncodeBlock(&b, proto.Version, sample); err != nil {
		out.err = err
		return out
	}
	if _, err := conn.Write(b.Buf); err != nil {
		out.err = err
		return out
	}
	b.Reset()
	for {
		times.Reset()
		values.Reset()
		block, err := readClientBlock(r, proto.Results{{Name: "time", Data: &times}, {Name: "value", Data: &values}})
		if err != nil {
			out.err = err
			return out
		}
		if block.End() {
			break
		}
		out.blocks++
		out.values = append(out.values, []uint64(values)...)
	}
	if fault == "lost-ack" {
		return out
	}
	proto.ServerCodeEndOfStream.Encode(&b)
	_, out.err = conn.Write(b.Buf)
	return out
}

func readClientBlock(r *proto.Reader, result proto.Result) (proto.Block, error) {
	code, err := r.UVarInt()
	if err != nil {
		return proto.Block{}, err
	}
	if proto.ClientCode(code) != proto.ClientCodeData {
		return proto.Block{}, fmt.Errorf("expected data, got %d", code)
	}
	var data proto.ClientData
	if err := data.DecodeAware(r, proto.Version); err != nil {
		return proto.Block{}, err
	}
	var block proto.Block
	err = block.DecodeBlock(r, proto.Version, result)
	return block, err
}

func checkWire(t *testing.T, finished <-chan wireOutcome, wantBlocks int, wantValues []uint64) {
	t.Helper()
	select {
	case out := <-finished:
		if out.err != nil || out.blocks != wantBlocks || !reflect.DeepEqual(out.values, wantValues) {
			t.Fatalf("wire blocks=%d values=%v err=%v, want %d %v", out.blocks, out.values, out.err, wantBlocks, wantValues)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("wire peer did not finish")
	}
}

func TestWriteRetriesOnlyBeforeInputWithRealDriver(t *testing.T) {
	for _, fault := range []string{"stale-idle", "before-input"} {
		t.Run(fault, func(t *testing.T) { testWriteRetriesBeforeInput(t, fault) })
	}
}

func testWriteRetriesBeforeInput(t *testing.T, firstFault string) {
	w, qc, cache, block := testWriter(t)
	var dials int
	var outcomes []<-chan wireOutcome
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		fault := ""
		if dials == 0 {
			fault = firstFault
		}
		dials++
		conn, done, err := wireConnection(ctx, fault)
		outcomes = append(outcomes, done)
		return conn, err
	}
	w.Write(0, cache)
	if dials != 2 || qc.counter.WriteSuccessCount != 2 || qc.counter.WriteFailedCount != 0 || qc.counter.WriteUncertainCount != 0 || qc.counter.RetryCount != 1 || qc.counter.RetryFailedCount != 0 {
		t.Fatalf("dials=%d counter=%+v", dials, qc.counter)
	}
	checkWire(t, outcomes[0], 0, nil)
	checkWire(t, outcomes[1], 1, []uint64{11, 22})
	if block.times.Location != time.UTC {
		t.Fatalf("DateTime inference lost: %v", block.times.Location)
	}
	assertFinalized(t, cache, block)
}

func TestWriteDoesNotReplayLostAcknowledgement(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	var dials int
	var done <-chan wireOutcome
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		dials++
		var conn writeConnection
		var err error
		conn, done, err = wireConnection(ctx, "lost-ack")
		return conn, err
	}
	w.Write(0, cache)
	if dials != 1 || qc.counter.WriteSuccessCount != 0 || qc.counter.WriteFailedCount != 2 || qc.counter.WriteUncertainCount != 2 || qc.counter.RetryCount != 0 || qc.conns[0] != nil {
		t.Fatalf("unsafe replay or accounting: dials=%d counter=%+v conn=%v", dials, qc.counter, qc.conns[0])
	}
	checkWire(t, done, 1, []uint64{11, 22})
	assertFinalized(t, cache, block)
}

func TestWriteSuccessfulInputHasNoDuplicateEOFTail(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	var done <-chan wireOutcome
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		var conn writeConnection
		var err error
		conn, done, err = wireConnection(ctx, "")
		return conn, err
	}
	w.Write(0, cache)
	if qc.counter.WriteSuccessCount != 2 || qc.counter.WriteFailedCount != 0 || qc.counter.RetryCount != 0 {
		t.Fatalf("counter=%+v", qc.counter)
	}
	checkWire(t, done, 1, []uint64{11, 22})
	assertFinalized(t, cache, block)
}

func TestWriteBoundsDialRetriesAndFinalizesOnce(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	var dials int
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("dial missing shared batch deadline")
		}
		dials++
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	w.Write(0, cache)
	if dials != writeMaxAttempts || qc.counter.WriteFailedCount != 2 || qc.counter.WriteSuccessCount != 0 || qc.counter.WriteUncertainCount != 0 || qc.counter.RetryCount != int64(writeMaxAttempts-1) || qc.counter.RetryFailedCount != int64(writeMaxAttempts-1) {
		t.Fatalf("unbounded/incorrect retry: dials=%d counter=%+v", dials, qc.counter)
	}
	assertFinalized(t, cache, block)
}

func TestWriteDoesNotRetryServerException(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	conn := &fakeConnection{do: func(context.Context, ch.Query) error {
		return &ch.Exception{Code: proto.Error(60), Message: "unknown table"}
	}}
	qc.conns[0] = conn
	w.Write(0, cache)
	if conn.closed != 1 || qc.counter.RetryCount != 0 || qc.counter.WriteFailedCount != 2 || qc.counter.WriteUncertainCount != 0 {
		t.Fatalf("counter=%+v closed=%d", qc.counter, conn.closed)
	}
	assertFinalized(t, cache, block)
}

func TestWriteDeadlineBoundsBackoff(t *testing.T) {
	_, qc, cache, block := testWriter(t)
	var calls int
	qc.conns[0] = &fakeConnection{do: func(context.Context, ch.Query) error { calls++; return io.EOF }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := cache.write(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || qc.counter.RetryCount != 0 {
		t.Fatalf("err=%v calls=%d counter=%+v", err, calls, qc.counter)
	}
	assertFinalized(t, cache, block)
}

func TestWriteUncertainRetryIsCountedOnce(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	first := &fakeConnection{do: func(context.Context, ch.Query) error { return io.EOF }}
	second := &fakeConnection{do: func(ctx context.Context, q ch.Query) error {
		if err := q.Input[0].Data.(proto.Inferable).Infer("DateTime('UTC')"); err != nil {
			t.Fatal(err)
		}
		if err := q.OnInput(ctx); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual([]uint64(block.values), []uint64{11, 22}) || block.resets != 0 {
			t.Fatal("batch changed before retry finished")
		}
		return io.ErrUnexpectedEOF
	}}
	qc.conns[0] = first
	qc.dial = func(context.Context, ch.Options) (writeConnection, error) { return second, nil }
	w.Write(0, cache)
	if qc.counter.WriteFailedCount != 2 || qc.counter.WriteUncertainCount != 2 || qc.counter.RetryCount != 1 || qc.counter.RetryFailedCount != 1 || first.closed != 1 || second.closed != 1 {
		t.Fatalf("counter=%+v closes=%d/%d", qc.counter, first.closed, second.closed)
	}
	assertFinalized(t, cache, block)
}

type optionalColumn struct {
	proto.ColUInt64
	inferred atomic.Bool
	prepared atomic.Bool
	state    atomic.Bool
}

func (c *optionalColumn) Infer(proto.ColumnType) error { c.inferred.Store(true); return nil }
func (c *optionalColumn) Prepare() error               { c.prepared.Store(true); return nil }
func (c *optionalColumn) EncodeState(*proto.Buffer)    { c.state.Store(true) }

func TestInputGateRestoresOptionalColumnInterfaces(t *testing.T) {
	col := &optionalColumn{ColUInt64: proto.ColUInt64{42}}
	cache := &Cache{prepare: "INSERT INTO test.samples VALUES", protoInput: proto.Input{{Name: "value", Data: col}}}
	conn := &fakeConnection{do: func(ctx context.Context, q ch.Query) error {
		if q.Input[0].Data.Rows() != 0 {
			t.Fatal("initial input is already nonempty")
		}
		if err := q.Input[0].Data.(proto.Inferable).Infer("UInt64"); err != nil {
			t.Fatal(err)
		}
		if err := q.OnInput(ctx); err != nil {
			t.Fatal(err)
		}
		if q.Input[0].Data != col {
			t.Fatal("real column not restored before encode")
		}
		var encoded proto.Buffer
		if err := (proto.Block{Columns: 1, Rows: 1}).EncodeBlock(&encoded, proto.Version, q.Input); err != nil {
			t.Fatal(err)
		}
		if err := q.OnInput(ctx); !errors.Is(err, io.EOF) || q.Input[0].Data.Rows() != 0 {
			t.Fatalf("EOF tail is not empty: %v", err)
		}
		return nil
	}}
	err, started := cache.writeSingleBlock(context.Background(), conn)
	if err != nil || !started || !col.inferred.Load() || !col.prepared.Load() || !col.state.Load() || col.Rows() != 1 || cache.protoInput[0].Data != col || cache.retryInput[0].Data != col {
		t.Fatalf("gate altered column semantics: err=%v started=%v", err, started)
	}
}

func TestResetConnectionReplacesLiveClient(t *testing.T) {
	w, qc, _, _ := testWriter(t)
	old := &fakeConnection{}
	fresh := &fakeConnection{}
	qc.conns[0] = old
	qc.dial = func(context.Context, ch.Options) (writeConnection, error) { return fresh, nil }
	if err := w.ResetConnection(0, 0); err != nil || old.closed != 1 || qc.conns[0] != fresh {
		t.Fatalf("reset did not replace client: %v", err)
	}
}

func TestEmptyCacheDoesNotDialOrReset(t *testing.T) {
	qc := &QueueContext{dial: func(context.Context, ch.Options) (writeConnection, error) {
		t.Fatal("empty batch dialed")
		return nil, nil
	}}
	block := new(testColumnBlock)
	cache := &Cache{queueContext: qc, columnBlock: block}
	if err := cache.Write(); err != nil || block.resets != 0 || cache.writeCounter != 0 {
		t.Fatalf("empty cache changed: %v", err)
	}
}

func TestWriteServerExceptionBeforeSampleKeepsOriginalError(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	var dials int
	var done <-chan wireOutcome
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		dials++
		var conn writeConnection
		var err error
		conn, done, err = wireConnection(ctx, "server-exception")
		return conn, err
	}
	w.Write(0, cache)
	if dials != 1 || qc.counter.RetryCount != 0 || qc.counter.WriteFailedCount != 2 || qc.counter.WriteUncertainCount != 0 {
		t.Fatalf("exception was obscured or marked supplied: dials=%d counter=%+v", dials, qc.counter)
	}
	checkWire(t, done, 0, nil)
	assertFinalized(t, cache, block)
}

func TestWriteEmptySampleEOSIsBoundedWithoutSupply(t *testing.T) {
	_, qc, cache, block := testWriter(t)
	var dials int
	var done <-chan wireOutcome
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		dials++
		var conn writeConnection
		var err error
		conn, done, err = wireConnection(ctx, "empty-eos")
		return conn, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := cache.write(ctx)
	var failure *batchWriteError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &failure) || failure.inputStarted || dials != 1 || qc.counter.RetryCount != 0 {
		t.Fatalf("empty sample/EOS was supplied or retried: err=%v dials=%d counter=%+v", err, dials, qc.counter)
	}
	checkWire(t, done, 0, nil)
	assertFinalized(t, cache, block)
}

func TestWriteRecoversAfterTransientDialRefusal(t *testing.T) {
	w, qc, cache, block := testWriter(t)
	const recoveryDelay = 550 * time.Millisecond
	start := time.Now()
	var dials int
	var done <-chan wireOutcome
	qc.dial = func(ctx context.Context, _ ch.Options) (writeConnection, error) {
		dials++
		if time.Since(start) < recoveryDelay {
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		}
		var conn writeConnection
		var err error
		conn, done, err = wireConnection(ctx, "")
		return conn, err
	}
	w.Write(0, cache)
	if qc.counter.WriteSuccessCount != 2 || qc.counter.WriteFailedCount != 0 || qc.counter.WriteUncertainCount != 0 || dials < 2 || qc.counter.RetryCount != int64(dials-1) || qc.counter.RetryFailedCount != int64(dials-2) {
		t.Fatalf("batch lost before backend recovered after %s: elapsed=%s dials=%d counter=%+v", recoveryDelay, time.Since(start), dials, qc.counter)
	}
	if elapsed := time.Since(start); elapsed < recoveryDelay || elapsed > FLUSH_TIMEOUT+time.Second {
		t.Fatalf("recovery outside bounded window: %s", elapsed)
	}
	checkWire(t, done, 1, []uint64{11, 22})
	assertFinalized(t, cache, block)
}
