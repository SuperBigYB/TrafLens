# Packet tunnel decoding

TrafLens replaces the public tunnel plugin's four empty decoders with ERSPAN,
TEB, Tencent GRE and VXLAN-GPE/NSH parsing. The public Rust signatures and
existing tunnel enums are retained. This is an implementation and parser
checkpoint; live tunneled capture, sustained collection and enterprise feature
parity require separate acceptance.

From the checkout root, run the locked packet-mode gate:

```sh
bash traflens/scripts/agent-packet.sh test-tunnel
bash traflens/scripts/agent-packet.sh parser-test
```

The tunnel gate runs 28 decoder wire tests and 26 Agent caller tests. The full
selected gate runs 127 tests: 99 Agent library tests and 28 tunnel-crate tests.
The complete packet library now completes 307 tests, with 295 passes and 12
failures. The six original tunnel failures pass; the remaining twelve match
the previous failure inventory. A selected gate is not a full-suite pass.

## Supported wire layouts

- ERSPAN types I, II and III over IPv4 GRE return the inner Ethernet frame.
  Type I has no ERSPAN feature header and ID zero. Types II and III extract
  the ten-bit session ID. The type III optional eight-byte platform subheader
  is length-checked and skipped. The standard ERSPAN sequence-only GRE profile
  is supported; checksum/key extensions and non-Ethernet frame types are not.
- TEB over IPv4 GRE handles checksum, key and sequence optional fields in wire
  order. Its tunnel ID is the full 32-bit key, or zero when absent.
- Tencent GRE accepts keyed IPv4 GRE version zero and the existing private
  version-one form, carrying inner IPv4 or IPv6. It synthesizes an Ethernet
  header before the inner IP header. The destination MAC suffix uses the low
  key half and the source suffix uses the high half, matching the existing Go
  decoder/FastPath contract. It is not a general PPTP decoder.
- VXLAN-GPE uses IPv4/UDP destination port 4790. Direct Ethernet, IPv4 and IPv6
  payloads and one NSH layer are supported. NSH metadata type one has its fixed
  24-byte header; type two validates variable TLV lengths and alignment. Raw IP
  payloads receive an Ethernet header using the original outer MACs. The VNI
  remains the tunnel ID. Unsupported versions, OAM and next protocols fail
  without changing the packet. Legacy P=0 accepts an Ethernet payload only.

Decoder offsets are relative to the start of the outer IP header. The caller
adds the actual outer L2 length and must receive an inner Ethernet frame.
GRE flags are decoded big-endian; the existing protocol argument is decoded
little-endian. These conventions are explicit and independent of host endian.
For non-mutating type I/II/III ERSPAN vectors with a 20-byte outer IPv4 header,
the offsets are 24/36/40; a type III platform header adds eight. The existing
NSH PCAP returns offset 74. Tencent's synthetic Ethernet header can overlap
outer addresses, so the Agent snapshots outer metadata before decoding and
commits it only after success. Nested tunnels retain the outermost identity.

## Caller boundary repairs

The Agent now checks captured and declared header bounds before reading,
handles the actual IPv4 IHL for UDP/VNI offsets, and returns 56 for an IPv6
Geneve header without options. Truncated payload captures are accepted when
all required headers are captured. Missing headers cannot be supplied by bytes
beyond declared IP/UDP lengths. No checksum validation is imposed on passive
captures because transmit offload may leave checksums unfinished.

Short frames, extreme L2 lengths, excessive tunnel tiers and unrepresentable
IPIP offsets return zero without modifying packet bytes or metadata. Minimal
valid IPIP no longer needs an ERSPAN-sized guard. The current IPIP copy layout
still requires outer IP header length greater than L2 length; for example a
20-byte IPv4 header with a 22-byte QinQ L2 header is safely rejected. Supporting
that layout needs a separate dispatcher contract change.

The Agent rejects unreassembled fragmented outer IPv4 packets. It does not
walk IPv6 extension chains, reassemble outer fragments, decode IPv6 jumbograms,
or dispatch outer-IPv6 GRE/GPE. Existing outer-IPv6 VXLAN and Geneve are covered.
These limitations remain explicit; the feature enums are not proof that all
possible wire variants work.

## Evidence and protocol references

Evidence is under `evidence/2026-10-26/tunnels/`. Tests include independent wire
vectors, the checked-in ERSPAN/TEB/NSH PCAPs, every required-header truncation,
options, declared-length padding, snaplen and transactional packet mutation.
An explicit negative control uses the old `52fa57a8b` caller with the new
decoders and new regression tests: ten of thirteen regressions fail, including
two panics, IPv6 Geneve offset 36 instead of 56 and Tencent address corruption.
The fixed caller passes all thirteen. This hybrid negative control is not a pristine
upstream build or a full reference-suite comparison.

The implementation uses public wire specifications and the existing open-source
Go decoder contract. Relevant primary references are
[GRE RFC 2784](https://www.rfc-editor.org/rfc/rfc2784.html),
[verified GRE erratum 3719](https://www.rfc-editor.org/errata/eid3719),
[GRE key/sequence RFC 2890](https://www.rfc-editor.org/rfc/rfc2890.html),
[NSH RFC 8300](https://www.rfc-editor.org/rfc/rfc8300.html),
[VXLAN-GPE draft 13](https://www.ietf.org/archive/id/draft-ietf-nvo3-vxlan-gpe-13.html)
and [Cisco ERSPAN draft 03](https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03).
The latter two are Internet-Drafts, not RFCs. DeepFlow's public
[configuration example](https://github.com/deepflowio/deepflow/blob/8741e924ff0ae3964a135985c51e5a6ce6bde397/server/agent_config/example.yaml)
describes the decapsulation selectors; TrafLens does not import private code.
