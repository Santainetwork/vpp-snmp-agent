package agentx

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// Hex vectors generated with the Python implementation
// (/root/vpp-snmp-agent/agentx/pdu.py):
//
//	PDU(AGENTX_OPEN_PDU).encode()
//	PDU(AGENTX_REGISTER_PDU) with oid = "1.3.6.1.2.1.1.3.0"
//	p = PDU(AGENTX_RESPONSE_PDU); p.values = [{"type": ..., "name": ..., "value": ...}]
func TestEncodeVectors(t *testing.T) {
	const (
		open      = "01011000000000000000000000000000000000140500000000000000000000074d794167656e7400"
		register  = "0103100000000000000000000000000000000018057f00000402000000000001000000010000000300000000"
		ping      = "010d100000000000000000000000000000000000"
		respInt   = "011210000000000000000000000000000000002400000000000000000002000004020000000000010000000100000003000000000000007b"
		respCtr64 = "011210000000000000000000000000000000002800000000000000000046000004020000000000010000000100000003000000000000010000000000"
		respStr   = "011210000000000000000000000000000000002800000000000000000004000004020000000000010000000100000005000000000000000465746830"
	)

	cases := []struct {
		name string
		pdu  PDU
		want string
	}{
		{"open", PDU{Type: PDU_OPEN}, open},
		{"register", PDU{Type: PDU_REGISTER, OID: "1.3.6.1.2.1.1.3.0"}, register},
		{"ping", PDU{Type: PDU_PING}, ping},
		{"response-integer", PDU{Type: PDU_RESPONSE, Values: []VarBind{
			{Type: TYPE_INTEGER, Name: "1.3.6.1.2.1.1.3.0", Value: int64(123)},
		}}, respInt},
		{"response-counter64", PDU{Type: PDU_RESPONSE, Values: []VarBind{
			{Type: TYPE_COUNTER64, Name: "1.3.6.1.2.1.1.3.0", Value: uint64(1) << 40},
		}}, respCtr64},
		{"response-octetstring", PDU{Type: PDU_RESPONSE, Values: []VarBind{
			{Type: TYPE_OCTETSTRING, Name: "1.3.6.1.2.1.1.5.0", Value: "eth0"},
		}}, respStr},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatalf("bad vector: %v", err)
			}
			got := tc.pdu.Encode()
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("Encode mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

// TestDecodeEncodeRoundTrip verifies the decoder against encoder output for the
// request PDUs the master agent sends.
func TestDecodeEncodeRoundTrip(t *testing.T) {
	resp := PDU{
		Type:          PDU_RESPONSE,
		SessionID:     7,
		TransactionID: 9,
		PacketID:      11,
		Values: []VarBind{
			{Type: TYPE_INTEGER, Name: "1.3.6.1.2.1.1.3.0", Value: uint32(42)},
			{Type: TYPE_OCTETSTRING, Name: "1.3.6.1.2.1.1.5.0", Value: "vpp0"},
			{Type: TYPE_COUNTER64, Name: "1.3.6.1.2.1.1.9.0", Value: uint64(123456789)},
			{Type: TYPE_OBJECTIDENTIFIER, Name: "1.3.6.1.2.1.1.2.0", Value: "1.3.6.1.4.1.9"},
		},
	}
	got, err := DecodePDU(resp.Encode())
	if err != nil {
		t.Fatalf("DecodePDU: %v", err)
	}
	if got.Type != PDU_RESPONSE || got.SessionID != 7 || got.TransactionID != 9 || got.PacketID != 11 {
		t.Fatalf("header mismatch: %+v", got)
	}
	if len(got.Values) != len(resp.Values) {
		t.Fatalf("varbind count = %d, want %d", len(got.Values), len(resp.Values))
	}
	for i, want := range resp.Values {
		if got.Values[i].Name != want.Name || got.Values[i].Type != want.Type {
			t.Fatalf("varbind %d = %+v, want %+v", i, got.Values[i], want)
		}
	}
	if got.Values[1].Value != "vpp0" {
		t.Fatalf("octet string = %v", got.Values[1].Value)
	}
	if got.Values[3].Value != "1.3.6.1.4.1.9" {
		t.Fatalf("oid value = %v", got.Values[3].Value)
	}
}

// TestDecodeSearchRange decodes a GETNEXT request the way a master agent sends
// it: a varbindlist of (start, end) OID pairs, where start encodes include=1.
func TestDecodeSearchRange(t *testing.T) {
	// Python encodes no payload for GET/GETNEXT, so build the search range list
	// by hand: start OID with include=1, then the end OID.
	payload := append(encodeOID("1.3.6.1.2.1.1", true), encodeOID("1.3.6.1.2.1.2", false)...)
	raw := PDU{Type: PDU_GETNEXT, SessionID: 3, TransactionID: 4, PacketID: 5}.Encode()
	raw = append(raw, payload...)
	raw[16], raw[17], raw[18], raw[19] = 0, 0, 0, byte(len(payload))

	got, err := DecodePDU(raw)
	if err != nil {
		t.Fatalf("DecodePDU: %v", err)
	}
	if got.Type != PDU_GETNEXT {
		t.Fatalf("type = %d", got.Type)
	}
	want := []SearchRange{{StartOID: "1.3.6.1.2.1.1", EndOID: "1.3.6.1.2.1.2", Include: true}}
	if !reflect.DeepEqual(got.RangeList, want) {
		t.Fatalf("ranges = %+v, want %+v", got.RangeList, want)
	}
}

func TestDataSetSortAndNextOID(t *testing.T) {
	ds := NewDataSet()
	ds.Set("1.3.6.1.2.1.1.10.0", "int", int64(10))
	ds.Set("1.3.6.1.2.1.1.3.0", "ticks", int64(30))
	ds.Set("1.3.6.1.2.1.1.2.0", "str", "sys")
	ds.Set("1.3.6.1.2.1.1.9.0", "u32", uint32(9))
	ds.Set("1.3.6.1.4.1.9.1", "u64", uint64(1))

	idx, data := ds.Data()
	wantIdx := []string{
		"1.3.6.1.2.1.1.2.0",
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.2.1.1.9.0",
		"1.3.6.1.2.1.1.10.0",
		"1.3.6.1.4.1.9.1",
	}
	if !reflect.DeepEqual(idx, wantIdx) {
		t.Fatalf("sorted index = %v, want %v", idx, wantIdx)
	}

	if v, ok := data["1.3.6.1.2.1.1.3.0"]; !ok || v.Type != TYPE_TIMETICKS || v.Value != int64(30) {
		t.Fatalf("ticks varbind = %+v", v)
	}
	if v, ok := data["1.3.6.1.2.1.1.9.0"]; !ok || v.Type != TYPE_COUNTER32 || v.Value != uint32(9) {
		t.Fatalf("u32 varbind = %+v", v)
	}
	if v, ok := data["1.3.6.1.4.1.9.1"]; !ok || v.Type != TYPE_COUNTER64 || v.Value != uint64(1) {
		t.Fatalf("u64 varbind = %+v", v)
	}
	if v, ok := data["1.3.6.1.2.1.1.2.0"]; !ok || v.Type != TYPE_OCTETSTRING || v.Value != "sys" {
		t.Fatalf("str varbind = %+v", v)
	}

	// Exact match yields the following OID; numeric (not string) ordering.
	cases := []struct{ from, want string }{
		{"1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0"},
		{"1.3.6.1.2.1.1.9.0", "1.3.6.1.2.1.1.10.0"},
		{"1.3.6.1.2.1.1.10.0", "1.3.6.1.4.1.9.1"},
		{"1.3.6.1.4.1.9.1", ""},
	}
	for _, tc := range cases {
		got := getNextOID(idx, data, tc.from, "1.3.6.1.4.1.9.2")
		if got != tc.want {
			t.Fatalf("getNextOID(%s) = %q, want %q", tc.from, got, tc.want)
		}
	}

	// No exact match: first OID inside [start, end] (network._get_next_oid's
	// arc-wise prefix walk). Entries outside the range yield "".
	rangeCases := []struct{ from, end, want string }{
		{"1.3.6.1.2.1.1.2", "1.3.6.1.2.1.1.255", "1.3.6.1.2.1.1.2.0"},
		{"1.3.6.1.2.1.1.5", "1.3.6.1.2.1.1.255", "1.3.6.1.2.1.1.9.0"},
		{"1.3.6.1.2.1.1.5", "1.3.6.1.2.1.1.6", ""},
		{"1.3.6.1.3", "1.3.6.1.3", ""},
	}
	for _, tc := range rangeCases {
		got := getNextOID(idx, data, tc.from, tc.end)
		if got != tc.want {
			t.Fatalf("getNextOID(%s,%s) = %q, want %q", tc.from, tc.end, got, tc.want)
		}
	}
}

func TestOIDPrefixTrick(t *testing.T) {
	// 1.3.6.1.2.x -> prefix byte holds the 5th arc, so subids start at x.
	got := encodeOID("1.3.6.1.2.1.1.3.0", false)
	want := "04020000" + "00000001" + "00000001" + "00000003" + "00000000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("encodeOID = %x, want %s", got, want)
	}
	// OIDs not under 1.3.6.1 get prefix 0 and keep all their arcs.
	got = encodeOID("1.3.6.1", false)
	want = "04000000" + "00000001" + "00000003" + "00000006" + "00000001"
	if hex.EncodeToString(got) != want {
		t.Fatalf("encodeOID(1.3.6.1) = %x, want %s", got, want)
	}
}
