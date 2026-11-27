// Package agentx is a Go port of the Python pyagentx client
// (agentx/{__init__,pdu,dataset,network,agent}.py) speaking the AgentX
// protocol to an SNMP master agent.
package agentx

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// PDU types (agentx.AGENTX_*_PDU in __init__.py).
const (
	PDU_OPEN     uint32 = 1
	PDU_CLOSE    uint32 = 2
	PDU_REGISTER uint32 = 3
	PDU_GET      uint32 = 5
	PDU_GETNEXT  uint32 = 6
	PDU_PING     uint32 = 13
	PDU_RESPONSE uint32 = 18
)

// SNMP value types (agentx.TYPE_* in __init__.py).
const (
	TYPE_INTEGER          uint16 = 2
	TYPE_OCTETSTRING      uint16 = 4
	TYPE_NULL             uint16 = 5
	TYPE_OBJECTIDENTIFIER uint16 = 6
	TYPE_IPADDRESS        uint16 = 64
	TYPE_COUNTER32        uint16 = 65
	TYPE_GAUGE32          uint16 = 66
	TYPE_TIMETICKS        uint16 = 67
	TYPE_OPAQUE           uint16 = 68
	TYPE_COUNTER64        uint16 = 70
	TYPE_NOSUCHOBJECT     uint16 = 128
	TYPE_NOSUCHINSTANCE   uint16 = 129
	TYPE_ENDOFMIBVIEW     uint16 = 130
)

// Error codes (agentx.ERROR_* in __init__.py).
const (
	ERROR_NOAGENTXERROR         uint16 = 0
	ERROR_GENERR                uint16 = 5
	ERROR_NOACCESS              uint16 = 6
	ERROR_WRONGTYPE             uint16 = 7
	ERROR_WRONGLENGTH           uint16 = 8
	ERROR_WRONGENCODING         uint16 = 9
	ERROR_WRONGVALUE            uint16 = 10
	ERROR_NOCREATION            uint16 = 11
	ERROR_INCONSISTENTVALUE     uint16 = 12
	ERROR_RESOURCEUNAVAILABLE   uint16 = 13
	ERROR_COMMITFAILED          uint16 = 14
	ERROR_UNDOFAILED            uint16 = 15
	ERROR_NOTWRITABLE           uint16 = 17
	ERROR_INCONSISTENTNAME      uint16 = 18
	ERROR_OPENFAILED            uint16 = 256
	ERROR_NOTOPEN               uint16 = 257
	ERROR_INDEXWRONGTYPE        uint16 = 258
	ERROR_INDEXALREADYALLOCATED uint16 = 259
	ERROR_INDEXNONEAVAILABLE    uint16 = 260
	ERROR_INDEXNOTALLOCATED     uint16 = 261
	ERROR_UNSUPPORTEDCONTEXT    uint16 = 262
	ERROR_DUPLICATEREGISTRATION uint16 = 263
	ERROR_UNKNOWNREGISTRATION   uint16 = 264
	ERROR_UNKNOWNAGENTCAPS      uint16 = 265
	ERROR_PARSEERROR            uint16 = 266
	ERROR_REQUESTDENIED         uint16 = 267
	ERROR_PROCESSINGERROR       uint16 = 268
)

// VarBind is one variable binding (PDU.value in pdu.py).
type VarBind struct {
	Type  uint16
	Name  string
	Value any
}

// SearchRange is one entry of a GET/GETNEXT varbindlist
// (the (start, end, include) tuples in pdu.py).
type SearchRange struct {
	StartOID string
	EndOID   string
	Include  bool
}

// PDU is a decoded or to-be-encoded AgentX PDU (class PDU in pdu.py).
type PDU struct {
	Type          uint32
	SessionID     uint32
	TransactionID uint32
	PacketID      uint32
	Error         uint16
	ErrorIndex    uint16
	Values        []VarBind
	RangeList     []SearchRange
	// OID is the registration sub-tree, used only when encoding REGISTER.
	OID string
}

// encodeOID mirrors PDU.encode_oid: 4-byte header (n_subid, prefix, include,
// reserved) then big-endian uint32 subids. The 1.3.6.1 prefix trick stores the
// 5th arc in the prefix byte when the OID starts with 1.3.6.1.
func encodeOID(oid string, include bool) []byte {
	parts := strings.Split(strings.Trim(oid, "."), ".")
	ids := make([]uint32, 0, len(parts))
	for _, p := range parts {
		var n uint32
		fmt.Sscan(p, &n)
		ids = append(ids, n)
	}
	prefix := uint8(0)
	if len(ids) > 5 && ids[0] == 1 && ids[1] == 3 && ids[2] == 6 && ids[3] == 1 {
		prefix = uint8(ids[4])
		ids = ids[5:]
	}
	buf := []byte{byte(len(ids)), prefix, 0, 0}
	if include {
		buf[2] = 1
	}
	for _, n := range ids {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], n)
		buf = append(buf, x[:]...)
	}
	return buf
}

// encodeOctet mirrors PDU.encode_octet: uint32 length, UTF-8 bytes, then zero
// padding to a 4-byte boundary.
func encodeOctet(s string) []byte {
	raw := []byte(s)
	buf := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(buf, uint32(len(raw)))
	copy(buf[4:], raw)
	return append(buf, make([]byte, (4-len(raw)%4)%4)...)
}

// encodeValue mirrors PDU.encode_value.
func encodeValue(v VarBind) []byte {
	buf := []byte{byte(v.Type >> 8), byte(v.Type), 0, 0}
	buf = append(buf, encodeOID(v.Name, false)...)
	put32 := func(n uint32) {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], n)
		buf = append(buf, x[:]...)
	}
	switch v.Type {
	case TYPE_INTEGER:
		put32(uint32(asInt64(v.Value)))
	case TYPE_COUNTER32, TYPE_GAUGE32, TYPE_TIMETICKS:
		put32(asUint32(v.Value))
	case TYPE_COUNTER64:
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], asUint64(v.Value))
		buf = append(buf, x[:]...)
	case TYPE_OBJECTIDENTIFIER:
		buf = append(buf, encodeOID(asString(v.Value), false)...)
	case TYPE_IPADDRESS, TYPE_OPAQUE, TYPE_OCTETSTRING:
		buf = append(buf, encodeOctet(asString(v.Value))...)
	case TYPE_NULL, TYPE_NOSUCHOBJECT, TYPE_NOSUCHINSTANCE, TYPE_ENDOFMIBVIEW:
		// No data.
	}
	return buf
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case uint32:
		return int64(n)
	case uint64:
		return int64(n)
	}
	return 0
}

func asUint32(v any) uint32 {
	switch n := v.(type) {
	case uint32:
		return n
	case int64:
		return uint32(n)
	case int:
		return uint32(n)
	case uint64:
		return uint32(n)
	}
	return 0
}

func asUint64(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case uint32:
		return uint64(n)
	case int64:
		return uint64(n)
	case int:
		return uint64(n)
	}
	return 0
}

func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// Encode mirrors PDU.encode: build the type-specific payload, then prepend the
// 20-byte header with flags|=0x10 (all ints network byte order).
func (p PDU) Encode() []byte {
	var payload []byte
	switch p.Type {
	case PDU_OPEN:
		// timeout=5, then 4 zero bytes for the (empty) agent OID, then "MyAgent".
		payload = append(payload, 5, 0, 0, 0, 0, 0, 0, 0)
		payload = append(payload, encodeOctet("MyAgent")...)
	case PDU_CLOSE, PDU_PING:
		// No extra data.
	case PDU_REGISTER:
		const (
			timeout    = 5
			priority   = 127
			rangeSubid = 0
		)
		payload = append(payload, timeout, priority, rangeSubid, 0)
		payload = append(payload, encodeOID(p.OID, false)...)
	case PDU_RESPONSE:
		payload = make([]byte, 8)
		binary.BigEndian.PutUint32(payload, 0) // sysUpTime
		binary.BigEndian.PutUint16(payload[4:], p.Error)
		binary.BigEndian.PutUint16(payload[6:], p.ErrorIndex)
		for _, v := range p.Values {
			payload = append(payload, encodeValue(v)...)
		}
	}

	header := make([]byte, 20)
	header[0] = 1 // version
	header[1] = byte(p.Type)
	header[2] = 0x10 // flags: network byte order
	header[3] = 0    // reserved
	binary.BigEndian.PutUint32(header[4:], p.SessionID)
	binary.BigEndian.PutUint32(header[8:], p.TransactionID)
	binary.BigEndian.PutUint32(header[12:], p.PacketID)
	binary.BigEndian.PutUint32(header[16:], uint32(len(payload)))
	return append(header, payload...)
}

// decodeOID mirrors PDU.decode_oid, returning the dotted OID, the include flag
// and the remaining buffer.
func decodeOID(b []byte) (oid string, include bool, rest []byte, err error) {
	if len(b) < 4 {
		return "", false, nil, fmt.Errorf("agentx: short OID header")
	}
	n := int(b[0])
	prefix := b[1]
	include = b[2] != 0
	b = b[4:]
	if len(b) < n*4 {
		return "", false, nil, fmt.Errorf("agentx: short OID subids")
	}
	var ids []uint32
	if prefix != 0 {
		ids = []uint32{1, 3, 6, 1, uint32(prefix)}
	}
	for i := 0; i < n; i++ {
		ids = append(ids, binary.BigEndian.Uint32(b[i*4:]))
	}
	parts := make([]string, len(ids))
	for i, x := range ids {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, "."), include, b[n*4:], nil
}

// decodeOctet mirrors PDU.decode_octet, honoring the 4-byte alignment padding.
func decodeOctet(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, fmt.Errorf("agentx: short octet header")
	}
	n := int(binary.BigEndian.Uint32(b))
	b = b[4:]
	pad := (4 - n%4) % 4
	if len(b) < n+pad {
		return "", nil, fmt.Errorf("agentx: short octet data")
	}
	return string(b[:n]), b[n+pad:], nil
}

// decodeValue mirrors PDU.decode_value.
func decodeValue(b []byte) (VarBind, []byte, error) {
	var v VarBind
	if len(b) < 4 {
		return v, nil, fmt.Errorf("agentx: short varbind")
	}
	v.Type = binary.BigEndian.Uint16(b)
	name, _, rest, err := decodeOID(b[4:])
	if err != nil {
		return v, nil, err
	}
	v.Name = name
	b = rest
	switch v.Type {
	case TYPE_INTEGER, TYPE_COUNTER32, TYPE_GAUGE32, TYPE_TIMETICKS:
		if len(b) < 4 {
			return v, nil, fmt.Errorf("agentx: short 32-bit value")
		}
		v.Value = binary.BigEndian.Uint32(b)
		b = b[4:]
	case TYPE_COUNTER64:
		if len(b) < 8 {
			return v, nil, fmt.Errorf("agentx: short 64-bit value")
		}
		v.Value = binary.BigEndian.Uint64(b)
		b = b[8:]
	case TYPE_OBJECTIDENTIFIER:
		oid, _, rest, err := decodeOID(b)
		if err != nil {
			return v, nil, err
		}
		v.Value = oid
		b = rest
	case TYPE_IPADDRESS, TYPE_OPAQUE, TYPE_OCTETSTRING:
		s, rest, err := decodeOctet(b)
		if err != nil {
			return v, nil, err
		}
		v.Value = s
		b = rest
	case TYPE_NULL, TYPE_NOSUCHOBJECT, TYPE_NOSUCHINSTANCE, TYPE_ENDOFMIBVIEW:
		v.Value = nil
	}
	return v, b, nil
}

// DecodePDU mirrors PDU.decode for GET, GETNEXT and RESPONSE PDUs.
func DecodePDU(buf []byte) (*PDU, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("agentx: short header (%d bytes)", len(buf))
	}
	p := &PDU{
		Type:          uint32(buf[1]),
		SessionID:     binary.BigEndian.Uint32(buf[4:]),
		TransactionID: binary.BigEndian.Uint32(buf[8:]),
		PacketID:      binary.BigEndian.Uint32(buf[12:]),
	}
	n := int(binary.BigEndian.Uint32(buf[16:]))
	if n > len(buf)-20 {
		return nil, fmt.Errorf("agentx: short payload")
	}
	d := buf[20 : 20+n]
	// flags bit 0x08 (context present) is not set by the master agents this
	// client talks to; pyagentx would skip a context octet here.
	switch p.Type {
	case PDU_RESPONSE:
		if len(d) < 8 {
			return nil, fmt.Errorf("agentx: short response header")
		}
		p.Error = binary.BigEndian.Uint16(d[4:])
		p.ErrorIndex = binary.BigEndian.Uint16(d[6:])
		d = d[8:]
		for len(d) > 0 {
			v, rest, err := decodeValue(d)
			if err != nil {
				return nil, err
			}
			p.Values = append(p.Values, v)
			d = rest
		}
	case PDU_GET, PDU_GETNEXT:
		for len(d) > 0 {
			start, include, rest, err := decodeOID(d)
			if err != nil {
				return nil, err
			}
			end, _, rest, err := decodeOID(rest)
			if err != nil {
				return nil, err
			}
			p.RangeList = append(p.RangeList, SearchRange{StartOID: start, EndOID: end, Include: include})
			d = rest
		}
	}
	return p, nil
}
