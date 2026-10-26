package protocolsmoke

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"

	flowpb "traflens.local/protocol-smoke/flowpb"
	statspb "traflens.local/protocol-smoke/statspb"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("fixtures", name+".wire"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func want(t *testing.T, field string, got, expected interface{}) {
	t.Helper()
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("%s: got %#v, want %#v", field, got, expected)
	}
}

// The wire input is encoded by protoc from text, independently of generated Go
// marshaling. Assertions use values chosen explicitly in the fixture contract.
func TestHTTPGoldenRequestResponse(t *testing.T) {
	var m flowpb.AppProtoLogsData
	if err := proto.Unmarshal(fixture(t, "http-session"), &m); err != nil {
		t.Fatal(err)
	}
	b := m.GetBase()
	if b == nil || b.GetHead() == nil || m.GetReq() == nil || m.GetResp() == nil {
		t.Fatal("HTTP session lost its base, head, request or response")
	}
	want(t, "HTTP1 protocol", b.GetHead().GetProto(), uint32(20))
	want(t, "session message type", b.GetHead().GetMsgType(), uint32(2))
	want(t, "response duration", b.GetHead().GetRrt(), uint64(2500))
	want(t, "flow id retains all 64 bits", b.GetFlowId(), uint64(18446744073709551600))
	want(t, "start time", b.GetStartTime(), uint64(1720000000000000))
	want(t, "end time", b.GetEndTime(), uint64(1720000000002500))
	want(t, "TCP protocol", b.GetProtocol(), uint32(6))
	want(t, "source IPv4", b.GetIpSrc(), uint32(167772161))
	want(t, "destination IPv4", b.GetIpDst(), uint32(167772162))
	want(t, "source port", b.GetPortSrc(), uint32(49152))
	want(t, "destination port", b.GetPortDst(), uint32(8080))
	want(t, "request TCP sequence", b.GetReqTcpSeq(), uint32(4294967200))
	want(t, "response TCP sequence", b.GetRespTcpSeq(), uint32(2147483650))
	want(t, "method", m.GetReq().GetReqType(), "GET")
	want(t, "domain", m.GetReq().GetDomain(), "api.example.test")
	want(t, "resource", m.GetReq().GetResource(), "/v1/items")
	want(t, "endpoint", m.GetReq().GetEndpoint(), "items.list")
	want(t, "response status Ok", m.GetResp().GetStatus(), uint32(0))
	want(t, "response HTTP code", m.GetResp().GetCode(), int32(200))
	want(t, "response result", m.GetResp().GetResult(), "OK")
	want(t, "HTTP version", m.GetVersion(), "1.1")
	want(t, "request length", m.GetReqLen(), int32(42))
	want(t, "response length", m.GetRespLen(), int32(128))
	want(t, "captured request bytes", m.GetCapturedRequestByte(), uint32(42))
	want(t, "captured response bytes", m.GetCapturedResponseByte(), uint32(128))
	want(t, "trace id", m.GetTraceInfo().GetTraceId(), "0123456789abcdef0123456789abcdef")
	want(t, "span id", m.GetTraceInfo().GetSpanId(), "0123456789abcdef")
	want(t, "parent span id", m.GetTraceInfo().GetParentSpanId(), "fedcba9876543210")
	want(t, "trace id list", m.GetTraceInfo().GetTraceIds(), []string{"0123456789abcdef0123456789abcdef"})
	want(t, "service name", m.GetExtInfo().GetServiceName(), "catalog")
	want(t, "attribute names", m.GetExtInfo().GetAttributeNames(), []string{"region"})
	want(t, "attribute values", m.GetExtInfo().GetAttributeValues(), []string{"lab"})
	want(t, "metric names", m.GetExtInfo().GetMetricsNames(), []string{"items"})
	want(t, "metric values", m.GetExtInfo().GetMetricsValues(), []float64{2.5})
	roundTrip(t, &m, func() proto.Message { return &flowpb.AppProtoLogsData{} })

	// Request/response discriminator values are from the pinned Rust enum, not
	// protobuf enums (the schema defines these fields as uint32).
	for _, msgType := range []uint32{0, 1} {
		m.Base.Head.MsgType = msgType
		if msgType == 0 {
			m.ReqLen = -1 // Explicitly preserve signed unknown-length sentinel.
			m.Resp = nil
		} else {
			m.Req = nil
			m.Resp = &flowpb.L7Response{Status: 3, Code: 503, Exception: "unavailable"}
		}
		roundTrip(t, &m, func() proto.Message { return &flowpb.AppProtoLogsData{} })
	}
}

func TestL4GoldenCounters(t *testing.T) {
	var m flowpb.TaggedFlow
	if err := proto.Unmarshal(fixture(t, "l4-flow"), &m); err != nil {
		t.Fatal(err)
	}
	f := m.GetFlow()
	if f == nil || f.GetFlowKey() == nil || f.GetMetricsPeerSrc() == nil || f.GetMetricsPeerDst() == nil || f.GetPerfStats() == nil {
		t.Fatal("L4 flow lost key, counters or performance statistics")
	}
	want(t, "flow id", f.GetFlowId(), uint64(18446744073709551600))
	want(t, "tap port", f.GetFlowKey().GetTapPort(), uint64(4294967297))
	want(t, "transport", f.GetFlowKey().GetProto(), uint32(6))
	want(t, "source byte count exceeds uint32", f.GetMetricsPeerSrc().GetByteCount(), uint64(4294967419))
	want(t, "source l3 bytes", f.GetMetricsPeerSrc().GetL3ByteCount(), uint64(4294967355))
	want(t, "source l4 bytes", f.GetMetricsPeerSrc().GetL4ByteCount(), uint64(4294967297))
	want(t, "source packet count exceeds uint32", f.GetMetricsPeerSrc().GetPacketCount(), uint64(4294967300))
	want(t, "source total bytes", f.GetMetricsPeerSrc().GetTotalByteCount(), uint64(8589934715))
	want(t, "source total packets", f.GetMetricsPeerSrc().GetTotalPacketCount(), uint64(4294967310))
	want(t, "signed source EPC", f.GetMetricsPeerSrc().GetL3EpcId(), int32(-2))
	want(t, "signed destination EPC", f.GetMetricsPeerDst().GetL3EpcId(), int32(-1))
	want(t, "destination bytes", f.GetMetricsPeerDst().GetByteCount(), uint64(9001))
	want(t, "destination packets", f.GetMetricsPeerDst().GetPacketCount(), uint64(30))
	want(t, "TCP retransmissions", f.GetPerfStats().GetTcp().GetTotalRetransCount(), uint32(4))
	want(t, "TX retransmissions", f.GetPerfStats().GetTcp().GetCountsPeerTx().GetRetransCount(), uint32(3))
	want(t, "TX zero window", f.GetPerfStats().GetTcp().GetCountsPeerTx().GetZeroWinCount(), uint32(2))
	want(t, "L7 requests", f.GetPerfStats().GetL7().GetRequestCount(), uint32(2))
	want(t, "L7 response duration sum", f.GetPerfStats().GetL7().GetRrtSum(), uint64(5000))
	want(t, "packed ACL list", f.GetAclGids(), []uint32{17, 65535})
	want(t, "packed aggregate flow ids", f.GetAggregatedFlowIds(), []uint64{4294967297, 18446744073709551600})
	roundTrip(t, &m, func() proto.Message { return &flowpb.TaggedFlow{} })
}

func TestStatsGoldenLabelsAndMetrics(t *testing.T) {
	var m statspb.Stats
	if err := proto.Unmarshal(fixture(t, "stats"), &m); err != nil {
		t.Fatal(err)
	}
	want(t, "timestamp", m.GetTimestamp(), uint64(1720000000))
	want(t, "name", m.GetName(), "traflens.protocol-smoke")
	want(t, "tag names", m.GetTagNames(), []string{"host", "interface"})
	want(t, "tag values", m.GetTagValues(), []string{"dev-lab", "test0"})
	want(t, "metric names", m.GetMetricsFloatNames(), []string{"rx_packets", "drop_ratio"})
	want(t, "metric values", m.GetMetricsFloatValues(), []float64{4294967297, 0.125})
	want(t, "organization", m.GetOrgId(), uint32(1))
	want(t, "team", m.GetTeamId(), uint32(2))
	roundTrip(t, &m, func() proto.Message { return &statspb.Stats{} })
}

func roundTrip(t *testing.T, original proto.Message, newMessage func() proto.Message) {
	t.Helper()
	b, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := newMessage()
	if err := proto.Unmarshal(b, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(original, decoded) {
		t.Fatalf("round trip changed %T: before=%v after=%v", original, original, decoded)
	}
	if got := proto.Size(original); got != len(b) {
		t.Errorf("size mismatch for %T: got %d, encoded %d", original, got, len(b))
	}
}

func TestUnknownFieldsForwardCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name       string
		newMessage func() proto.Message
	}{
		{"http-session", func() proto.Message { return &flowpb.AppProtoLogsData{} }},
		{"l4-flow", func() proto.Message { return &flowpb.TaggedFlow{} }},
		{"stats", func() proto.Message { return &statspb.Stats{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := fixture(t, tc.name)
			baseline := tc.newMessage()
			if err := proto.Unmarshal(wire, baseline); err != nil {
				t.Fatal(err)
			}
			// Legal future field numbers, outside protobuf's reserved 19000-19999.
			unknown := varint(nil, uint64(65000<<3))
			unknown = varint(unknown, 4294967297)
			unknown = varint(unknown, uint64(65001<<3|2))
			unknown = varint(unknown, 6)
			unknown = append(unknown, []byte("future")...)
			unknown = varint(unknown, uint64(65002<<3|1))
			unknown = append(unknown, 1, 2, 3, 4, 5, 6, 7, 8)
			unknown = varint(unknown, uint64(65003<<3|5))
			unknown = append(unknown, 9, 10, 11, 12)
			decoded := tc.newMessage()
			if err := proto.Unmarshal(append(append([]byte(nil), wire...), unknown...), decoded); err != nil {
				t.Fatalf("new fields rejected: %v", err)
			}
			round, err := proto.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(round, unknown) {
				t.Fatal("unknown field bytes were lost during remarshal")
			}
			knownOnly := proto.Clone(decoded)
			proto.DiscardUnknown(knownOnly)
			if !proto.Equal(baseline, knownOnly) {
				t.Fatal("future fields changed known values")
			}
			roundTrip(t, decoded, tc.newMessage)
			if err := proto.Unmarshal(append(append([]byte(nil), wire...), 0x80), tc.newMessage()); err == nil {
				t.Fatal("truncated field key accepted")
			}
			// A length-delimited field claiming 100 bytes with only one available.
			truncated := varint(nil, uint64(65001<<3|2))
			truncated = append(truncated, 100, 'x')
			if err := proto.Unmarshal(append(append([]byte(nil), wire...), truncated...), tc.newMessage()); err == nil {
				t.Fatal("truncated unknown field body accepted")
			}
		})
	}
}

func varint(dst []byte, v uint64) []byte {
	var b [10]byte
	n := binary.PutUvarint(b[:], v)
	return append(dst, b[:n]...)
}

// Pin wire numbers and scalar/message types. Re-encoding alone would miss a
// coordinated schema renumbering because both sides could make the same error.
func TestWireFieldContracts(t *testing.T) {
	type field struct {
		message, name string
		number        int32
		kind          descriptor.FieldDescriptorProto_Type
	}
	for _, tc := range []struct {
		filename string
		fields   []field
	}{
		{"flow_log.proto", []field{
			{"TaggedFlow", "flow", 1, descriptor.FieldDescriptorProto_TYPE_MESSAGE},
			{"Flow", "flow_id", 5, descriptor.FieldDescriptorProto_TYPE_UINT64},
			{"Flow", "aggregated_flow_ids", 27, descriptor.FieldDescriptorProto_TYPE_UINT64},
			{"FlowMetricsPeer", "byte_count", 1, descriptor.FieldDescriptorProto_TYPE_UINT64},
			{"FlowMetricsPeer", "packet_count", 4, descriptor.FieldDescriptorProto_TYPE_UINT64},
			{"FlowMetricsPeer", "l3_epc_id", 10, descriptor.FieldDescriptorProto_TYPE_INT32},
			{"AppProtoLogsData", "base", 1, descriptor.FieldDescriptorProto_TYPE_MESSAGE},
			{"AppProtoLogsData", "req_len", 9, descriptor.FieldDescriptorProto_TYPE_INT32},
			{"AppProtoLogsData", "req", 11, descriptor.FieldDescriptorProto_TYPE_MESSAGE},
			{"AppProtoLogsData", "resp", 12, descriptor.FieldDescriptorProto_TYPE_MESSAGE},
			{"AppProtoLogsData", "trace_info", 14, descriptor.FieldDescriptorProto_TYPE_MESSAGE},
			{"L7Request", "req_type", 1, descriptor.FieldDescriptorProto_TYPE_STRING},
			{"L7Response", "code", 2, descriptor.FieldDescriptorProto_TYPE_INT32},
			{"AppProtoHead", "rrt", 5, descriptor.FieldDescriptorProto_TYPE_UINT64},
		}},
		{"stats.proto", []field{
			{"Stats", "timestamp", 1, descriptor.FieldDescriptorProto_TYPE_UINT64},
			{"Stats", "tag_names", 3, descriptor.FieldDescriptorProto_TYPE_STRING},
			{"Stats", "metrics_float_values", 8, descriptor.FieldDescriptorProto_TYPE_DOUBLE},
			{"Stats", "org_id", 9, descriptor.FieldDescriptorProto_TYPE_UINT32},
			{"Stats", "team_id", 10, descriptor.FieldDescriptorProto_TYPE_UINT32},
		}},
	} {
		t.Run(tc.filename, func(t *testing.T) {
			reader, err := gzip.NewReader(bytes.NewReader(proto.FileDescriptor(tc.filename)))
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			var fd descriptor.FileDescriptorProto
			if err := proto.Unmarshal(data, &fd); err != nil {
				t.Fatal(err)
			}
			for _, expected := range tc.fields {
				found := false
				for _, m := range fd.GetMessageType() {
					if m.GetName() != expected.message {
						continue
					}
					for _, f := range m.GetField() {
						if f.GetName() != expected.name {
							continue
						}
						found = true
						want(t, expected.message+"."+expected.name+" number", f.GetNumber(), expected.number)
						want(t, expected.message+"."+expected.name+" type", f.GetType(), expected.kind)
					}
				}
				if !found {
					t.Errorf("missing field %s.%s", expected.message, expected.name)
				}
			}
		})
	}
}
