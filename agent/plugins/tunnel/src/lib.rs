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

mod gre;
mod tencent_gre;
mod vxlan_gpe;

pub fn decapsulate_gpe_vxlan(packet: &mut [u8], l2_len: usize) -> Option<(usize, u32)> {
    vxlan_gpe::decapsulate_gpe_vxlan(packet, l2_len)
}

pub fn decapsulate_erspan(
    packet: &[u8],
    l2_len: usize,
    flags: u16,
    gre_protocol_type: u16,
    ip_header_size: usize,
) -> Option<(usize, u32)> {
    gre::decapsulate_erspan(packet, l2_len, flags, gre_protocol_type, ip_header_size)
}

pub fn decapsulate_teb(
    packet: &[u8],
    l2_len: usize,
    flags: u16,
    ip_header_size: usize,
) -> Option<(usize, u32)> {
    gre::decapsulate_teb(packet, l2_len, flags, ip_header_size)
}

pub fn decapsulate_tencent_gre(
    packet: &mut [u8],
    l2_len: usize,
    flags: u16,
    gre_protocol_type: u16,
    ip_header_size: usize,
) -> Option<(usize, u32)> {
    tencent_gre::decapsulate_tencent_gre(packet, l2_len, flags, gre_protocol_type, ip_header_size)
}
