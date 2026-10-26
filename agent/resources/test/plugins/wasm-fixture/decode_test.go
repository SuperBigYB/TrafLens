// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/base64"
	"testing"
)

func TestFixtureMessages(t *testing.T) {
	req, _ := base64.StdEncoding.DecodeString("CgZkb21haW4SCHJlc291cmNlGgR0eXBlIghlbmRwb2ludA==")
	var r fixtureReq
	if err := r.UnmarshalVT(req); err != nil || r != (fixtureReq{"domain", "resource", "type", "endpoint"}) {
		t.Fatalf("request: %+v %v", r, err)
	}
	resp, _ := base64.StdEncoding.DecodeString("COcHEgZyZXN1bHQ=")
	var s fixtureResp
	if err := s.UnmarshalVT(resp); err != nil || s != (fixtureResp{999, "result"}) {
		t.Fatalf("response: %+v %v", s, err)
	}
}
func TestFixtureMalformedMessages(t *testing.T) {
	for _, b := range [][]byte{{0}, {0x80}, {0x08, 1}, {0x0a, 5, 'x'}, {0x0a, 0x80}} {
		if err := new(fixtureReq).UnmarshalVT(b); err == nil {
			t.Errorf("request accepted %x", b)
		}
	}
	for _, b := range [][]byte{{0}, {0x0a, 0}, {0x08, 0x80}, {0x08, 0x80, 0x80, 0x80, 0x80, 0x10}, {0x12, 3, 'x'}} {
		if err := new(fixtureResp).UnmarshalVT(b); err == nil {
			t.Errorf("response accepted %x", b)
		}
	}
}
func TestFixtureUnknownFieldsAndReset(t *testing.T) {
	r := fixtureReq{Domain: "old"}
	if err := r.UnmarshalVT([]byte{0x28, 1, 0x0a, 1, 'x'}); err != nil || r.Domain != "x" {
		t.Fatalf("unknown field: %+v %v", r, err)
	}
	if err := r.UnmarshalVT(nil); err != nil || r != (fixtureReq{}) {
		t.Fatalf("reset: %+v %v", r, err)
	}
}
