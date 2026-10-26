// Copyright 2026 TrafLens authors.
// SPDX-License-Identifier: Apache-2.0
// Adapted from the Apache-2.0 embedded fixture in agent/src/plugin/wasm/test.rs.

package main

import (
	"bytes"
	"encoding/base64"
	"github.com/deepflowio/deepflow-wasm-go-sdk/sdk"
	"github.com/valyala/fastjson"
	"net/url"
	"strconv"
)

func checkReqCtx(baseCtx *sdk.ParseCtx) {
	payload, _ := baseCtx.GetPayload()
	sdk.Error("saddr %v: %v", baseCtx.SrcIP.IP, baseCtx.SrcPort)
	sdk.Error("daddr %v: %v", baseCtx.DstIP.IP, baseCtx.DstPort)
	sdk.Error("l4: %v", baseCtx.L4)
	sdk.Error("l7: %v", baseCtx.L7)
	sdk.Error("dir: %v", baseCtx.Direction)
	sdk.Error("ebpf type: %v", baseCtx.EbpfType)
	sdk.Error("proc name: %v", baseCtx.ProcName)
	sdk.Error("time: %v", baseCtx.Time)
	sdk.Error("flowid: %v", baseCtx.FlowID)
	sdk.Error("buf_size: %v", baseCtx.BufSize)
	sdk.Error("payload: %v ", payload)

	checkEq("1.2.3.4", baseCtx.SrcIP.IP.String())
	checkEq(12345, int(baseCtx.SrcPort))
	checkEq("5.6.7.8", baseCtx.DstIP.IP.String())
	checkEq(8080, int(baseCtx.DstPort))
	checkEq(sdk.TCP, baseCtx.L4)
	checkEq(sdk.DirectionRequest, baseCtx.Direction)
	checkEq(sdk.EbpfTypeTracePoint, baseCtx.EbpfType)
	checkEq(expectedProcName, baseCtx.ProcName)
	checkEq(uint64(12345678), baseCtx.Time)
	checkEq(uint64(1234567), baseCtx.FlowID)
	checkEq(uint16(999), baseCtx.BufSize)
}

func checkRespCtx(baseCtx *sdk.ParseCtx) {
	payload, _ := baseCtx.GetPayload()

	sdk.Error("saddr %v: %v", baseCtx.SrcIP.IP, baseCtx.SrcPort)
	sdk.Error("daddr %v: %v", baseCtx.DstIP.IP, baseCtx.DstPort)
	sdk.Error("l4: %v", baseCtx.L4)
	sdk.Error("l7: %v", baseCtx.L7)
	sdk.Error("dir: %v", baseCtx.Direction)
	sdk.Error("ebpf type: %v", baseCtx.EbpfType)
	sdk.Error("time: %v", baseCtx.Time)
	sdk.Error("flowid: %v", baseCtx.FlowID)
	sdk.Error("buf_size: %v", baseCtx.BufSize)
	sdk.Error("p: %v ", payload)

	checkEq("5.6.7.8", baseCtx.SrcIP.IP.String())
	checkEq(uint16(8080), baseCtx.SrcPort)
	checkEq("1.2.3.4", baseCtx.DstIP.IP.String())
	checkEq(uint16(12345), baseCtx.DstPort)
	checkEq(sdk.TCP, baseCtx.L4)
	checkEq(sdk.DirectionResponse, baseCtx.Direction)
	checkEq(sdk.EbpfTypeTracePoint, baseCtx.EbpfType)
	checkEq(expectedProcName, baseCtx.ProcName)
	checkEq(uint64(12345678), baseCtx.Time)
	checkEq(uint64(1234567), baseCtx.FlowID)
	checkEq(uint16(999), baseCtx.BufSize)
}

type parser struct {
	sdk.DefaultParser
}

func (p parser) HookIn() []sdk.HookBitmap {
	return []sdk.HookBitmap{
		sdk.HOOK_POINT_HTTP_REQ,
		sdk.HOOK_POINT_HTTP_RESP,
		sdk.HOOK_POINT_PAYLOAD_PARSE,
	}
}

func checkEq(a, b interface{}) {
	if a != b {
		sdk.Error("%v and %v not equal", a, b)
		panic("")
	}
}

func (p parser) OnHttpReq(ctx *sdk.HttpReqCtx) sdk.Action {
	sdk.Warn("================ enter http req ==================")
	baseCtx := &ctx.BaseCtx
	payload, err := baseCtx.GetPayload()
	if err != nil {
		sdk.Error("%v", err)
		panic(err)
	}

	checkReqCtx(baseCtx)

	sdk.Error("path: %v ", ctx.Path)
	sdk.Error("host: %v ", ctx.Host)
	sdk.Error("ua: %v ", ctx.UserAgent)
	sdk.Error("ref: %v ", ctx.Referer)

	checkEq(20, int(baseCtx.L7))
	checkEq("/test?a=1&b=2&c=test", ctx.Path)
	checkEq("abc.com", ctx.Host)
	checkEq("deepflow", ctx.UserAgent)
	checkEq("aaa.com", ctx.Referer)
	checkEq(
		"POST /test?a=1&b=2&c=test HTTP/1.1\r\nUser-Agent: deepflow\r\nreferer: aaa.com\r\nHost: abc.com\r\nContent-Type: application/json\r\n\r\n",
		string(payload),
	)

	u, err := url.Parse(ctx.Path)
	if err != nil {
		panic(err)
	}
	q := u.Query()

	attr := []sdk.KeyVal{
		{
			Key: "a",
			Val: q.Get("a"),
		},

		{
			Key: "b",
			Val: q.Get("b"),
		},
		{
			Key: "c",
			Val: q.Get("c"),
		},
		{
			Key: "empty",
			Val: "",
		},
	}

	trace := &sdk.Trace{
		TraceID:      "aaa",
		SpanID:       "bbb",
		ParentSpanID: "ccc",
	}
	return sdk.HttpReqActionAbortWithResult(&sdk.Request{
		ReqType:  "rewrite req type",
		Domain:   "rewrite domain",
		Resource: "rewrite resource",
		Endpoint: "/rewrite endpoint",
	}, trace, attr)
}

func (p parser) OnHttpResp(ctx *sdk.HttpRespCtx) sdk.Action {
	sdk.Warn("================ enter http resp ==================")
	baseCtx := &ctx.BaseCtx
	payload, err := baseCtx.GetPayload()
	if err != nil {
		sdk.Error("%v", err)
		panic(err)
	}

	checkRespCtx(baseCtx)

	sdk.Error("p: %v ", string(payload))

	checkEq(20, int(baseCtx.L7))
	checkEq(uint16(200), ctx.Code)
	checkEq(sdk.RespStatusOk, ctx.Status)

	checkEq("HTTP/1.1 200 Ok\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"user_id\":123, \"name\":\"kkk\"}}", string(payload))
	sep := bytes.Index(payload, []byte("\r\n\r\n"))
	if sep < 0 {
		panic("missing response header terminator")
	}
	body := payload[sep+4:]

	checkEq(`{"data":{"user_id":123, "name":"kkk"}}`, string(body))

	userID := fastjson.GetInt(body, "data", "user_id")
	userName := fastjson.GetString(body, "data", "name")
	var code int32 = 599
	status := sdk.RespStatusServerErr
	return sdk.HttpRespActionAbortWithResult(&sdk.Response{
		Status:    &status,
		Code:      &code,
		Result:    "rewrite result",
		Exception: "rewrite exception",
	}, nil, []sdk.KeyVal{
		{
			Key: "user_id",
			Val: strconv.Itoa(userID),
		},

		{
			Key: "username",
			Val: userName,
		},
	})
}

func (p parser) OnCheckPayload(baseCtx *sdk.ParseCtx) (uint8, string, uint8) {
	sdk.Warn("================ check payload ==================")
	checkReqCtx(baseCtx)
	payload, err := baseCtx.GetPayload()
	if err != nil {
		sdk.Error("%v", err)
		panic(err)
	}
	checkEq("CgZkb21haW4SCHJlc291cmNlGgR0eXBlIghlbmRwb2ludA==", base64.StdEncoding.EncodeToString(payload))

	a := &fixtureReq{}
	if err := a.UnmarshalVT(payload); err != nil {
		sdk.Error("unmarshal pb fail: $v", err)
		panic(err)
	}

	checkEq(0, int(baseCtx.L7))
	checkEq(a.Domain, "domain")
	checkEq(a.Resource, "resource")
	checkEq(a.Type, "type")
	checkEq(a.Endpoint, "endpoint")

	return 1, "test", 1
}

func (p parser) OnParsePayload(baseCtx *sdk.ParseCtx) sdk.Action {
	sdk.Warn("================ parse payload ==================")
	payload, err := baseCtx.GetPayload()
	if err != nil {
		sdk.Error("%v", err)
		panic(err)
	}
	trace := &sdk.Trace{
		TraceID:      "11111",
		SpanID:       "22222",
		ParentSpanID: "33333",
	}
	switch baseCtx.Direction {
	case sdk.DirectionRequest:
		checkReqCtx(baseCtx)
		checkEq("CgZkb21haW4SCHJlc291cmNlGgR0eXBlIghlbmRwb2ludA==", base64.StdEncoding.EncodeToString(payload))
		a := &fixtureReq{}
		if err := a.UnmarshalVT(payload); err != nil {
			sdk.Error("unmarshal pb fail: $v", err)
			panic(err)
		}

		checkEq(1, int(baseCtx.L7))
		checkEq(a.Domain, "domain")
		checkEq(a.Resource, "resource")
		checkEq(a.Type, "type")
		checkEq(a.Endpoint, "endpoint")
		reqLen := 999
		respLen := 9999
		requestID := uint32(666)

		return sdk.ParseActionAbortWithL7Info([]*sdk.L7ProtocolInfo{
			{
				ReqLen:    &reqLen,
				RespLen:   &respLen,
				RequestID: &requestID,
				Req: &sdk.Request{
					ReqType:  a.Type,
					Domain:   a.Domain,
					Resource: a.Resource,
					Endpoint: a.Endpoint,
				},
				Resp:  nil,
				Trace: trace,
				Kv: []sdk.KeyVal{
					{
						Key: "k1",
						Val: "",
					}, {
						Key: "k2",
						Val: "v2",
					},
				},
				ProtocolMerge: true,
				IsEnd:         true,
			},
			{
				ReqLen:    &reqLen,
				RespLen:   &respLen,
				RequestID: &requestID,
				Req: &sdk.Request{
					ReqType:  a.Type,
					Domain:   a.Domain,
					Resource: a.Resource,
					Endpoint: a.Endpoint,
				},
				Resp:  nil,
				Trace: trace,
				Kv: []sdk.KeyVal{
					{
						Key: "k3",
						Val: "v3",
					}, {
						Key: "k4",
						Val: "v4",
					},
				},
				ProtocolMerge: true,
				IsEnd:         true,
			},
		})

	case sdk.DirectionResponse:
		checkRespCtx(baseCtx)
		checkEq(1, int(baseCtx.L7))
		checkEq("COcHEgZyZXN1bHQ=", base64.StdEncoding.EncodeToString(payload))
		a := &fixtureResp{}
		if err := a.UnmarshalVT(payload); err != nil {
			sdk.Error("unmarshal pb fail: $v", err)
			panic(err)
		}
		checkEq(a.Result, "result")
		checkEq(a.Status, uint32(999))

		reqLen := 999
		respLen := 9999
		requestID := uint32(666)
		code := int32(999)
		status := sdk.RespStatusOk
		return sdk.ParseActionAbortWithL7Info([]*sdk.L7ProtocolInfo{
			{
				ReqLen:    &reqLen,
				RespLen:   &respLen,
				RequestID: &requestID,
				Req:       nil,
				Resp: &sdk.Response{
					Status:    &status,
					Code:      &code,
					Result:    "result",
					Exception: "exception",
				},
				Trace: trace,
				Kv: []sdk.KeyVal{
					{
						Key: "k1",
						Val: "v1",
					}, {
						Key: "k2",
						Val: "v2",
					},
				},
				ProtocolMerge: true,
				IsEnd:         true,
			},
			{
				ReqLen:    &reqLen,
				RespLen:   &respLen,
				RequestID: &requestID,
				Req:       nil,
				Resp: &sdk.Response{
					Status:    &status,
					Code:      &code,
					Result:    "result",
					Exception: "exception",
				},
				Trace: trace,
				Kv: []sdk.KeyVal{
					{
						Key: "k3",
						Val: "",
					}, {
						Key: "k4",
						Val: "v4",
					},
				},
				ProtocolMerge: true,
				IsEnd:         true,
			},
		})
	default:
		panic("unreachable")
	}
}

func main() {
	sdk.Warn("wasm register parser")
	sdk.SetParser(parser{})
}
