// SPDX-License-Identifier: Apache-2.0

package ckwriter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	ch "github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"
)

const (
	writeRetryBackoff    = 100 * time.Millisecond
	writeRetryMaxBackoff = time.Second
	writeMaxAttempts     = 13 // initial attempt plus twelve retries, within the batch deadline
)

type queryConnection interface {
	Do(context.Context, ch.Query) error
}

type writeConnection interface {
	queryConnection
	IsClosed() bool
	Close() error
}

// A post-supply failure may mean the server committed the block but its reply
// was lost. It must not be replayed without server-side deduplication.
type batchWriteError struct {
	err          error
	inputStarted bool
}

func (e *batchWriteError) Error() string {
	return fmt.Sprintf("batch item write block failed: %s", e.err)
}
func (e *batchWriteError) Unwrap() error { return e.err }

func (qc *QueueContext) closeConn(index int) {
	if index >= 0 && index < len(qc.conns) && qc.conns[index] != nil {
		_ = qc.conns[index].Close()
		qc.conns[index] = nil
	}
}

func (qc *QueueContext) initConnContext(ctx context.Context, index int) error {
	if index < 0 || index >= len(qc.addrs) || index >= len(qc.conns) {
		return fmt.Errorf("conn index (%d) exceeds address/connection range", index)
	}
	qc.closeConn(index)
	options := ch.Options{
		Address:          qc.addrs[index],
		User:             qc.user,
		Password:         qc.password,
		HandshakeTimeout: time.Minute,
		DialTimeout:      5 * time.Second,
	}
	var (
		conn writeConnection
		err  error
	)
	if qc.dial != nil {
		conn, err = qc.dial(ctx, options)
	} else {
		var client *ch.Client
		client, err = ch.Dial(ctx, options)
		if err == nil {
			conn = client
		}
	}
	if err != nil {
		return err
	}
	if IsNil(conn) {
		return errors.New("dial returned an empty connection")
	}
	qc.conns[index] = conn
	return nil
}

// The adapter is used only before input supply. Inference happens before the
// first OnInput callback, so it must still reach the underlying column.
type emptyInputColumn struct {
	proto.ColInput
	sampleSeen *atomic.Bool
}

func (emptyInputColumn) Rows() int { return 0 }
func (c emptyInputColumn) Infer(t proto.ColumnType) error {
	if infer, ok := c.ColInput.(proto.Inferable); ok {
		if err := infer.Infer(t); err != nil {
			return err
		}
	}
	c.sampleSeen.Store(true)
	return nil
}

func retryableWriteError(err error) bool {
	if ch.IsException(err) {
		return false
	}
	var networkError net.Error
	return errors.Is(err, ch.ErrClosed) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.As(err, &networkError)
}

func (c *Cache) Write() error {
	ctx, cancel := context.WithTimeout(context.Background(), FLUSH_TIMEOUT)
	defer cancel()
	return c.write(ctx)
}

func (c *Cache) write(ctx context.Context) error {
	if c.size == 0 {
		return nil
	}
	// CKItems have already been released by Add. Keep their serialized columns
	// and row order until all safe attempts finish, then finalize exactly once.
	defer func() {
		c.writeCounter++
		c.lastWriteTime = time.Now()
		c.size = 0
		c.columnBlock.Reset()
	}()
	qc := c.queueContext
	if qc.connCount <= 0 {
		return &batchWriteError{err: errors.New("no ClickHouse connections")}
	}
	index := c.writeCounter % qc.connCount
	c.protoInput = c.columnBlock.ToInput(c.protoInput[:0])
	if len(c.protoInput) == 0 || IsNil(c.protoInput[0].Data) || c.protoInput[0].Data.Rows() == 0 {
		return &batchWriteError{err: errors.New("nonempty cache has no input rows")}
	}
	var failure *batchWriteError
	backoff := writeRetryBackoff
	for attempt := 0; attempt < writeMaxAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return &batchWriteError{err: ctx.Err()}
			case <-timer.C:
			}
			backoff = min(backoff*2, writeRetryMaxBackoff)
		}
		if err := ctx.Err(); err != nil {
			return &batchWriteError{err: err}
		}
		if attempt > 0 {
			qc.counter.RetryCount++ // additional attempts, not rows
		}
		var err error
		if qc.conns[index] == nil || qc.conns[index].IsClosed() {
			err = qc.initConnContext(ctx, index)
		}
		started := false
		if err == nil {
			err, started = c.writeSingleBlock(ctx, qc.conns[index])
		}
		if err == nil {
			return nil
		}
		qc.closeConn(index)
		if attempt > 0 {
			qc.counter.RetryFailedCount++
		}
		failure = &batchWriteError{err: err, inputStarted: started}
		if started || ctx.Err() != nil || !retryableWriteError(err) {
			return failure
		}
	}
	return failure
}

func (c *Cache) writeSingleBlock(ctx context.Context, conn writeConnection) (error, bool) {
	c.retryInput = append(c.retryInput[:0], c.protoInput...)
	input := c.retryInput
	original := input[0].Data
	var sampleSeen atomic.Bool
	empty := emptyInputColumn{ColInput: original, sampleSeen: &sampleSeen}
	input[0].Data = empty
	defer func() { input[0].Data = original }()
	var started atomic.Bool
	// This gate is specific to INSERT VALUES without inline values or external
	// data. OnInput is otherwise called after a nonempty first block is sent.
	err := conn.Do(ctx, ch.Query{
		Body:  c.prepare,
		Input: input,
		OnInput: func(inputCtx context.Context) error {
			if !started.Load() {
				if !sampleSeen.Load() {
					// ch-go closes its column-info channel before canceling on
					// receive failure. Preserve that original EOF/Exception;
					// never supply rows from an empty closed-channel result.
					<-inputCtx.Done()
					return inputCtx.Err()
				}
				if err := inputCtx.Err(); err != nil {
					return err
				}
				started.Store(true)
				input[0].Data = original
				return nil
			}
			// ch-go sends a nonempty io.EOF tail again. Hide only its row count;
			// do not Reset the retained block or mutate the real column data.
			input[0].Data = empty
			return io.EOF
		},
	})
	return err, started.Load()
}
