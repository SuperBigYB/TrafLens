/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package flow_metrics

import (
	"reflect"
	"testing"
)

func TestMarshalTraffic(t *testing.T) {
	var buffer [1024]byte
	var l int

	t1 := Traffic{
		PacketTx:   1,
		PacketRx:   2,
		ByteTx:     3,
		ByteRx:     4,
		L3ByteTx:   12,
		L3ByteRx:   13,
		L4ByteTx:   14,
		L4ByteRx:   15,
		NewFlow:    6,
		ClosedFlow: 7,
		L7Request:  8,
		L7Response: 9,
	}
	l = t1.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet=3i,packet_tx=1i,packet_rx=2i,byte_tx=3i,byte_rx=4i,byte=7i,l3_byte_tx=12i,l3_byte_rx=13i,l4_byte_tx=14i,l4_byte_rx=15i,new_flow=6i,closed_flow=7i"+
		",l7_request=8i,l7_response=9i" {
		t.Error("MarshalTo()实现不正确")
	}

	t2 := Traffic{
		ByteTx:  3,
		NewFlow: 4,
	}
	l = t2.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet=0i,byte_tx=3i,byte=3i,new_flow=4i" {
		t.Error("MarshalTo()实现不正确")
	}
}

func TestReverse(t *testing.T) {
	t1 := Traffic{
		PacketTx:   1,
		PacketRx:   2,
		ByteTx:     3,
		ByteRx:     4,
		NewFlow:    6,
		ClosedFlow: 7,
		L7Request:  8,
		L7Response: 9,
		L3ByteTx:   12,
		L3ByteRx:   13,
		L4ByteTx:   14,
		L4ByteRx:   15,
	}
	t2 := Traffic{
		PacketTx:   2,
		PacketRx:   1,
		ByteTx:     4,
		ByteRx:     3,
		NewFlow:    6,
		ClosedFlow: 7,
		L7Request:  8,
		L7Response: 9,
		L3ByteTx:   13,
		L3ByteRx:   12,
		L4ByteTx:   15,
		L4ByteRx:   14,
	}

	t1.Reverse()
	if t1 != t2 {
		t.Error("Reverse()实现不正确")
	}
}

func initMeter(m interface{}, n uint64) {
	v := reflect.ValueOf(m)
	if v.IsNil() {
		return
	}

	v = reflect.Indirect(v)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Uint64, reflect.Uint32:
			f.SetUint(n)
		default:
			continue
		}
	}
}

func TestMerge(t *testing.T) {
	t1, t2 := &Traffic{}, &Traffic{}
	initMeter(t1, 1)
	initMeter(t2, 2)
	t.Log(t1)
	t1.ConcurrentMerge(t1)
	if *t1 != *t2 {
		t.Errorf("Traffic ConcurrentMerge failed, expected:%v, actual:%v", t2, t1)
	}

	l1, l2 := &Latency{}, &Latency{
		RTTMax: 1, RTTClientMax: 1, RTTServerMax: 1,
		SRTMax: 1, ARTMax: 1, RRTMax: 1, CITMax: 1,
		RTTSum: 2, RTTClientSum: 2, RTTServerSum: 2,
		SRTSum: 2, ARTSum: 2, RRTSum: 2, CITSum: 2,
		RTTCount: 2, RTTClientCount: 2, RTTServerCount: 2,
		SRTCount: 2, ARTCount: 2, RRTCount: 2, CITCount: 2,
	}
	initMeter(l1, 1)
	l1.ConcurrentMerge(l1)
	if *l1 != *l2 {
		t.Errorf("Latency ConcurrentMerge failed, expected:%v, actual:%v", l2, l1)
	}

	p1, p2 := &Performance{}, &Performance{}
	initMeter(p1, 1)
	initMeter(p2, 2)
	p1.ConcurrentMerge(p1)
	if *p1 != *p2 {
		t.Errorf("Performance ConcurrentMerge failed, expected:%v, actual:%v", p2, p1)
	}

	a1, a2 := &Anomaly{}, &Anomaly{}
	initMeter(a1, 1)
	initMeter(a2, 2)
	a1.ConcurrentMerge(a1)
	if *a1 != *a2 {
		t.Errorf("Anomaly ConcurrentMerge failed, expected:%v, actual:%v", a2, a1)
	}
}

func TestMarshalAnomaly(t *testing.T) {
	a := Anomaly{}
	initMeter(&a, 1)
	actual := make([]byte, 1000)
	n := a.MarshalTo(actual)
	expected := "client_rst_flow=1i,server_rst_flow=1i," +
		"server_syn_miss=1i,client_ack_miss=1i," +
		"client_half_close_flow=1i,server_half_close_flow=1i," +
		"client_source_port_reuse=1i,server_reset=1i,server_queue_lack=1i," +
		"client_establish_other_rst=1i,server_establish_other_rst=1i," +
		"tcp_timeout=1i," +
		"client_establish_fail=3i,server_establish_fail=4i,tcp_establish_fail=7i," +
		"l7_client_error=1i,l7_server_error=1i,l7_timeout=1i,l7_error=2i,ooo_tx=1i,ooo_rx=1i"
	if string(actual[:n]) != expected {
		t.Errorf("Anomaly MarshalTo failed, \n\texpected:%v\n\tactual:  %v\n", expected, string(actual[:n]))
	}
}

func TestAnomalyMergeOutOfOrderCounters(t *testing.T) {
	a := Anomaly{OooTx: 3, OooRx: 5}
	b := Anomaly{OooTx: 7, OooRx: 11}
	a.ConcurrentMerge(&b)
	if a.OooTx != 10 || a.OooRx != 16 {
		t.Fatalf("out-of-order counts were lost: %+v", a)
	}
	if b.OooTx != 7 || b.OooRx != 11 {
		t.Fatal("merge modified its source")
	}
	b.SequentialMerge(&b)
	if b.OooTx != 14 || b.OooRx != 22 {
		t.Fatalf("self merge did not preserve both counts: %+v", b)
	}
}

func TestMarshalLatencyClientIdleTime(t *testing.T) {
	latency := Latency{CITSum: 17, CITCount: 2, CITMax: 11}
	buffer := make([]byte, 1024)
	size := latency.MarshalTo(buffer)
	if actual := string(buffer[:size]); actual != "cit_sum=17i,cit_count=2i,cit_max=11i" {
		t.Fatalf("invalid client idle time fields: %s", actual)
	}
}

func TestMarshalPerformanceSynackRegression(t *testing.T) {
	performance := Performance{RetransSynack: 3}
	buffer := make([]byte, 1024)
	size := performance.MarshalTo(buffer)
	if actual := string(buffer[:size]); actual != "retrans_synack=3i" {
		t.Fatalf("invalid SYNACK retransmission field: %s", actual)
	}
}
