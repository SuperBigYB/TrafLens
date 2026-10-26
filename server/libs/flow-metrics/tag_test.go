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
	"encoding/binary"
	"math"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

func TestHasEdgeTagField(t *testing.T) {
	c := IPPath
	if !c.HasEdgeTagField() {
		t.Error("Edge Tag处理不正确")
	}
	c = IP
	if c.HasEdgeTagField() {
		t.Error("Edge Tag处理不正确")
	}
}

func TestInt16Unmarshal(t *testing.T) {
	for i := math.MinInt16; i <= math.MaxInt16; i++ {
		v, err := unmarshalUint16WithSpecialID(marshalUint16WithSpecialID(int16(i)))
		if err != nil || int16(i) != v {
			t.Errorf("Int16序列化反序列化[%d]不正确", i)
		}
		v = unmarshalInt32WithSpecialID(MarshalInt32WithSpecialID(int32(i)))
		if int16(i) != v {
			t.Errorf("Int32序列化反序列化[%d]不正确", i)
		}
	}
}

func TestNegativeID(t *testing.T) {
	f := Field{L3EpcID: datatype.EPC_FROM_DEEPFLOW}
	if f.NewTag(L3EpcID).ToKVString() != ",l3_epc_id=-1" {
		t.Error("int16值处理得不正确")
	}
	f = Field{L3EpcID: 32767}
	if f.NewTag(L3EpcID).ToKVString() != ",l3_epc_id=32767" {
		t.Error("int16值处理得不正确")
	}
}

func TestCloneTagWithIPv6Fields(t *testing.T) {
	var ip [net.IPv6len]byte
	for i := range ip {
		ip[i] = byte(i)
	}
	tagOrigin := AcquireTag()
	defer ReleaseTag(tagOrigin)
	tagOrigin.Field = Field{IsIPv4: 0}
	tagOrigin.IP6 = ip[:net.IPv6len]
	tagOrigin.IP61 = append(net.IP(nil), ip[:]...)
	tagOrigin.Code = IPPath
	tagOrigin.GlobalThreadID = 112
	tagOrigin.id = "original"
	tagCloned := CloneTag(tagOrigin)
	defer ReleaseTag(tagCloned)
	if !tagCloned.IP6.Equal(tagOrigin.IP6) {
		t.Error("CloneTag产生的tag和原tag字段不一致")
	}
	if !tagCloned.IP61.Equal(tagOrigin.IP61) || tagCloned.Code != tagOrigin.Code ||
		tagCloned.GlobalThreadID != tagOrigin.GlobalThreadID || tagCloned.id != tagOrigin.id {
		t.Error("CloneTag did not preserve destination IPv6 or tag metadata")
	}
	tagCloned.IP6[0] = 255
	if tagCloned.IP6.Equal(tagOrigin.IP6) {
		t.Error("CloneTag产生的tag和原tag共享了字段")
	}
	tagCloned.IP61[0] = 254
	if tagCloned.IP61.Equal(tagOrigin.IP61) {
		t.Error("CloneTag shares the destination IPv6 backing array")
	}
	tagOrigin.IP6[1] = 253
	tagOrigin.IP61[1] = 252
	if tagCloned.IP6[1] != 1 || tagCloned.IP61[1] != 1 {
		t.Error("mutating the original IPv6 fields changed the clone")
	}
}

func TestCloneTagWithNilAndEmptyIPv6Fields(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip6  net.IP
		ip61 net.IP
	}{
		{name: "nil"},
		{name: "empty", ip6: net.IP{}, ip61: net.IP{}},
		{name: "mixed", ip61: net.IP{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &Tag{Field: Field{IP6: tc.ip6, IP61: tc.ip61}, Code: IPPath, id: "empty"}
			cloned := CloneTag(original)
			defer ReleaseTag(cloned)
			if (cloned.IP6 == nil) != (tc.ip6 == nil) || (cloned.IP61 == nil) != (tc.ip61 == nil) ||
				len(cloned.IP6) != len(tc.ip6) || len(cloned.IP61) != len(tc.ip61) {
				t.Error("CloneTag changed nil or empty IPv6 fields")
			}
			if cloned.Code != original.Code || cloned.id != original.id {
				t.Error("CloneTag did not preserve tag metadata")
			}
		})
	}
}

type Strings []string

func (s Strings) Len() int           { return len(s) }
func (s Strings) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Strings) Less(i, j int) bool { return s[i] < s[j] }

func parseTagkeys(b []byte) []string {
	str := string(b)
	ret := make([]string, 0)
	splits := strings.Split(str, ",")
	for _, s := range splits {
		if index := strings.Index(s, "="); index != -1 {
			ret = append(ret, s[:index])
		}
	}
	return ret
}

func TestMarshallToInfluxdb(t *testing.T) {
	b := make([]byte, MAX_STRING_LENGTH)
	f := Field{IsIPv4: 1}
	tag := &Tag{Field: f}
	tag.GlobalThreadID = 112
	tag.Code = ^(HostIDPath | IPPath | L3DevicePath | L3EpcIDPath | RegionIDPath | SubnetIDPath | PodNodeIDPath | AZIDPath | PodGroupIDPath | PodNSIDPath | PodIDPath | PodClusterIDPath | ResourcePath)

	l := tag.MarshalTo(b)
	strs := parseTagkeys(b[:l])
	cloneStrs := make([]string, 0)
	cloneStrs = append(cloneStrs, strs...)
	sort.Sort(Strings(strs))
	if strs[0] < "_id" {
		t.Error("tag的keys在打包时, 所有key都必须小于'_id', 当前最小的key是:", strs[0])
	}

	for i, s := range cloneStrs {
		if s != strs[i] {
			t.Error("tag的keys在打包时, 没有按字典顺序排序在:", s)
		}
	}

	tag.Code = ^(HostID | IP | L3Device | L3EpcID | RegionID | SubnetID | PodNodeID | AZID | PodGroupID | PodNSID | PodID | PodClusterID | Resource)
	l = tag.MarshalTo(b)
	strs = parseTagkeys(b[:l])
	cloneStrs = cloneStrs[:0]
	cloneStrs = append(cloneStrs, strs...)
	sort.Sort(Strings(strs))
	if strs[0] < "_id" {
		t.Error("tag的keys在打包时, 所有key都必须小于'_id', 当前最小的key是:", strs[0])
	}

	for i, s := range cloneStrs {
		if s != strs[i] {
			t.Error("tag的keys在打包时, 没有按字典顺序排序在:", s)
		}
	}
}

func TestMarshalTagIPv6Path(t *testing.T) {
	tag := Tag{
		Field: Field{IP6: net.ParseIP("2001:db8::1"), IP61: net.ParseIP("2001:db8::2")},
		Code:  IPPath,
	}
	if actual := tag.ToKVString(); actual != ",ip_0=2001:db8::1,ip_1=2001:db8::2,ip_version=6" {
		t.Fatalf("invalid IPv6 path tags: %s", actual)
	}
}

func TestMarshalTagMixedCodesAreSorted(t *testing.T) {
	for _, ipv4 := range []uint8{0, 1} {
		tag := Tag{
			Field: Field{GlobalThreadID: 112, IsIPv4: ipv4,
				IP6: net.ParseIP("2001:db8::1"), IP61: net.ParseIP("2001:db8::2")},
			Code: ^Code(0),
		}
		keys := parseTagkeys([]byte(tag.ToKVString()))
		if len(keys) != 77 {
			t.Fatalf("IPv4=%d: serialized %d keys, want 77", ipv4, len(keys))
		}
		if !sort.StringsAreSorted(keys) {
			t.Errorf("IPv4=%d: tag keys are not sorted: %v", ipv4, keys)
		}
	}
}

func TestMarshalTagResourceFields(t *testing.T) {
	tag := Tag{
		Field: Field{
			AutoInstanceID: 1, AutoInstanceID1: 2, AutoInstanceType: 3, AutoInstanceType1: 4,
			AutoServiceID: 5, AutoServiceID1: 6, AutoServiceType: 7, AutoServiceType1: 8,
		},
		Code: Resource | ResourcePath,
	}
	expected := ",auto_instance_id=1,auto_instance_id_0=1,auto_instance_id_1=2" +
		",auto_instance_type=3,auto_instance_type_0=3,auto_instance_type_1=4" +
		",auto_service_id=5,auto_service_id_0=5,auto_service_id_1=6" +
		",auto_service_type=7,auto_service_type_0=7,auto_service_type_1=8"
	if actual := tag.ToKVString(); actual != expected {
		t.Fatalf("resource tag values or order changed: %s", actual)
	}
}

func checkTagAndMiniTagEqual(tag *Tag, miniTag *MiniTag) bool {
	expectedCode := miniTag.Code
	if expectedCode&Direction != 0 && expectedCode.HasEdgeTagField() {
		expectedCode = expectedCode&^Direction | TAPSide
	}
	// Decoding legacy agent tags adds process and signal-source dimensions.
	if expectedCode&IPPath != 0 {
		expectedCode |= GPIDPath | SignalSource
	} else if expectedCode != TRAFFIC_POLICY {
		expectedCode |= GPID | SignalSource
	}
	if tag.Code != expectedCode {
		return false
	}
	if tag.GlobalThreadID != miniTag.GlobalThreadID {
		return false
	}

	srcIP, dstIP := miniTag.IP(), miniTag.IP1()
	srcEpc := MarshalInt32WithSpecialID(int32(miniTag.L3EpcID))
	dstEpc := MarshalInt32WithSpecialID(int32(miniTag.L3EpcID1))

	code := tag.Code

	if code&IP != 0 {
		if tag.IsIPv4 == 0 && miniTag.IsIPv6 != 0 {
			if !tag.IP6.Equal(srcIP) {
				return false
			}
		} else if tag.IsIPv4 != 0 && miniTag.IsIPv6 == 0 {
			if tag.IP != binary.BigEndian.Uint32(srcIP) {
				return false
			}
		} else {
			return false
		}
	}
	if code&L3EpcID != 0 {
		if tag.L3EpcID != srcEpc {
			return false
		}
	}

	if code&IPPath != 0 {
		if tag.IsIPv4 == 0 && miniTag.IsIPv6 != 0 {
			if !tag.IP6.Equal(srcIP) {
				return false
			}
			if !tag.IP61.Equal(dstIP) {
				return false
			}
		} else if tag.IsIPv4 != 0 && miniTag.IsIPv6 == 0 {
			if tag.IP != binary.BigEndian.Uint32(srcIP) {
				return false
			}
			if tag.IP1 != binary.BigEndian.Uint32(dstIP) {
				return false
			}
		} else {
			return false
		}
	}
	if code&L3EpcIDPath != 0 {
		if tag.L3EpcID != srcEpc {
			return false
		}
		if tag.L3EpcID1 != dstEpc {
			return false
		}
	}

	if code&ACLGID != 0 {
		if tag.ACLGID != miniTag.ACLGID {
			return false
		}
	}
	if code&Protocol != 0 {
		if tag.Protocol != miniTag.Protocol {
			return false
		}
	}
	if code&ServerPort != 0 {
		if tag.ServerPort != miniTag.ServerPort {
			return false
		}
	}
	if code&VTAPID != 0 {
		if tag.VTAPID != miniTag.VTAPID {
			return false
		}
	}
	if code&TAPType != 0 {
		if tag.TAPType != miniTag.TAPType {
			return false
		}
	}
	if code&TAPSide != 0 {
		if !(tag.TAPSide == Client && miniTag.Direction == ClientToServer || tag.TAPSide == Server && miniTag.Direction == ServerToClient) {
			return false
		}
	}

	if code&Direction != 0 && tag.Role != miniTag.Direction.ToRole() {
		return false
	}
	// The protobuf transport shares server_port with tunnel_ip_id.
	if code&TunnelIPID != 0 && tag.TunnelIPID != miniTag.ServerPort {
		return false
	}
	return true
}

func TestEncodeMiniTag(t *testing.T) {
	encoder := &codec.SimpleEncoder{}
	decoder := &codec.SimpleDecoder{}

	sideMiniTag := &MiniTag{
		MiniField: &MiniField{
			IsIPv6:     0,
			rawIP:      [net.IPv6len]byte{10, 11, 1, 123},
			L3EpcID:    15,
			VTAPID:     24,
			Protocol:   layers.IPProtocolTCP,
			ServerPort: 5324,
			Direction:  ClientToServer,
			TAPType:    CLOUD,
			ACLGID:     16,
			TunnelIPID: 5324,
		},
		Code: IP | L3EpcID | VTAPID | Protocol | ServerPort | Direction | TAPType | ACLGID | TunnelIPID,
	}

	pbMtagE := &pb.MiniTag{}
	sideMiniTag.WriteToPB(pbMtagE)
	encoder.WritePB(pbMtagE)

	decoder.Init(encoder.Bytes())
	pbMtagD := &pb.MiniTag{}
	decoder.ReadPB(pbMtagD)

	sideTag := &Tag{}
	sideTag.ReadFromPB(pbMtagD)

	if !checkTagAndMiniTagEqual(sideTag, sideMiniTag) {
		t.Error("mini tag and tag mismatch")
		t.Error("tag:     ", sideTag)
		t.Error("mini tag:", sideMiniTag)
	}

	encoder.Reset()

	edgeMiniTag := &MiniTag{
		MiniField: &MiniField{
			IsIPv6:     1,
			rawIP:      [net.IPv6len]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			rawIP1:     [net.IPv6len]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			L3EpcID:    15,
			L3EpcID1:   16,
			VTAPID:     24,
			Protocol:   layers.IPProtocolTCP,
			ServerPort: 5324,
			Direction:  ClientToServer,
			TAPType:    CLOUD,
			ACLGID:     16,
			TunnelIPID: 5324,
		},
		Code: IPPath | L3EpcIDPath | VTAPID | Protocol | ServerPort | Direction | TAPType | ACLGID | TunnelIPID,
	}

	pbMtagE.Reset()
	edgeMiniTag.WriteToPB(pbMtagE)
	encoder.WritePB(pbMtagE)
	decoder.Init(encoder.Bytes())

	pbMtagD.Reset()
	edgeTag := &Tag{}
	decoder.ReadPB(pbMtagD)
	edgeTag.ReadFromPB(pbMtagD)

	if !checkTagAndMiniTagEqual(edgeTag, edgeMiniTag) {
		t.Error("mini tag and tag mismatch")
		t.Error("tag:     ", edgeTag)
		t.Error("mini tag:", edgeMiniTag)
	}

	encoder.Reset()
	edgeMiniTag.Direction = ServerToClient

	pbMtagE.Reset()
	edgeMiniTag.WriteToPB(pbMtagE)
	encoder.WritePB(pbMtagE)
	decoder.Init(encoder.Bytes())

	pbMtagD.Reset()
	decoder.ReadPB(pbMtagD)
	edgeTag = &Tag{}
	edgeTag.ReadFromPB(pbMtagD)

	if !checkTagAndMiniTagEqual(edgeTag, edgeMiniTag) {
		t.Error("mini tag and tag mismatch")
		t.Error("tag:     ", edgeTag)
		t.Error("mini tag:", edgeMiniTag)
	}
}

func TestDirectionEnum(t *testing.T) {
	clients := []DirectionEnum{ClientToServer, ClientNodeToServer, ClientHypervisorToServer, ClientGatewayHypervisorToServer, ClientGatewayToServer}
	for _, c := range clients {
		if !c.IsClientToServer() {
			t.Errorf("%v is client to server", c)
		}
		if c.IsServerToClient() {
			t.Errorf("%v is not server to client", c)
		}
	}

	servers := []DirectionEnum{ServerToClient, ServerNodeToClient, ServerHypervisorToClient, ServerGatewayHypervisorToClient, ServerGatewayToClient}
	for _, c := range servers {
		if !c.IsServerToClient() {
			t.Errorf("%v is server to client", c)
		}
		if c.IsClientToServer() {
			t.Errorf("%v is not client to server", c)
		}
	}
}

func TestDirectionToTAPSide(t *testing.T) {
	directions := []DirectionEnum{
		ClientToServer, ServerToClient, LocalToLocal,
		ClientNodeToServer, ServerNodeToClient,
		ClientHypervisorToServer, ServerHypervisorToClient,
		ClientGatewayHypervisorToServer, ServerGatewayHypervisorToClient,
		ClientGatewayToServer, ServerGatewayToClient,
	}
	tapSides := []TAPSideEnum{
		Client, Server, Local,
		ClientNode, ServerNode,
		ClientHypervisor, ServerHypervisor,
		ClientGatewayHypervisor, ServerGatewayHypervisor,
		ClientGateway, ServerGateway,
	}
	for i, d := range directions {
		if to := d.ToTAPSide(); to != tapSides[i] {
			t.Errorf("direction %v to tapSide %v error, should be %v", d, to, tapSides[i])
		}
	}
}

func TestPutTAPPort(t *testing.T) {
	bs := make([]byte, 16)
	for _, tc := range []struct {
		input  uint64
		output string
	}{
		{0, "00000000"},
		{1, "00000001"},
		{15, "0000000f"},
		{65535, "0000ffff"},
		{65535 << 8, "00ffff00"},
	} {
		putTAPPort(bs, tc.input)
		if string(bs[:TAP_PORT_STR_LEN]) != tc.output {
			t.Errorf("putTAPPort(%d)应为%s实为%s", tc.input, tc.output, bs[:TAP_PORT_STR_LEN])
		}
	}
}
