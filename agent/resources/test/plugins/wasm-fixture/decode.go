// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"google.golang.org/protobuf/encoding/protowire"
)

// These two input messages are fixture-local, independent of the SDK output ABI.
type fixtureReq struct{ Domain, Resource, Type, Endpoint string }
type fixtureResp struct {
	Status uint32
	Result string
}

func decodeFields(data []byte, field func(protowire.Number, protowire.Type, []byte) (int, error)) error {
	for len(data) > 0 {
		n, t, k := protowire.ConsumeTag(data)
		if k < 0 {
			return protowire.ParseError(k)
		}
		data = data[k:]
		k, err := field(n, t, data)
		if err != nil {
			return err
		}
		if k < 0 {
			return protowire.ParseError(k)
		}
		data = data[k:]
	}
	return nil
}
func textField(n protowire.Number, t protowire.Type, data []byte, dst *string) (int, error) {
	if t != protowire.BytesType {
		return 0, fmt.Errorf("field %d: expected string wire type", n)
	}
	v, k := protowire.ConsumeString(data)
	if k < 0 {
		return k, nil
	}
	*dst = v
	return k, nil
}
func (r *fixtureReq) UnmarshalVT(data []byte) error {
	*r = fixtureReq{}
	return decodeFields(data, func(n protowire.Number, t protowire.Type, b []byte) (int, error) {
		switch n {
		case 1:
			return textField(n, t, b, &r.Domain)
		case 2:
			return textField(n, t, b, &r.Resource)
		case 3:
			return textField(n, t, b, &r.Type)
		case 4:
			return textField(n, t, b, &r.Endpoint)
		}
		return protowire.ConsumeFieldValue(n, t, b), nil
	})
}
func (r *fixtureResp) UnmarshalVT(data []byte) error {
	*r = fixtureResp{}
	return decodeFields(data, func(n protowire.Number, t protowire.Type, b []byte) (int, error) {
		switch n {
		case 1:
			if t != protowire.VarintType {
				return 0, fmt.Errorf("status: expected varint")
			}
			v, k := protowire.ConsumeVarint(b)
			if k < 0 {
				return k, nil
			}
			if v > 0xffffffff {
				return 0, fmt.Errorf("status overflow")
			}
			r.Status = uint32(v)
			return k, nil
		case 2:
			return textField(n, t, b, &r.Result)
		}
		return protowire.ConsumeFieldValue(n, t, b), nil
	})
}
