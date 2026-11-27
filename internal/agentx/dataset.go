package agentx

import (
	"sort"
	"strconv"
	"strings"
)

// ValType mirrors the oid_type strings accepted by DataSet.set in dataset.py.
type ValType string

const (
	ValInt       ValType = "int"
	ValStr       ValType = "str"
	ValOID       ValType = "oid"
	ValIP        ValType = "ip"
	ValU32       ValType = "u32"
	ValGauge32   ValType = "gauge32"
	ValTicks     ValType = "ticks"
	ValU64       ValType = "u64"
	ValCounter32 ValType = "counter32"
	ValCounter64 ValType = "counter64"
)

// DataSet is the port of class DataSet in dataset.py. Set() maps an OID to a
// typed VarBind; Data() exposes the OIDs sorted by numeric arc order plus a
// lookup map, matching the data/data_idx pair network.update maintains.
type DataSet struct {
	data map[string]VarBind
}

// NewDataSet returns an empty DataSet.
func NewDataSet() *DataSet {
	return &DataSet{data: map[string]VarBind{}}
}

// Set stores a typed value for oid, translating ValType to an AgentX type code
// the same way DataSet.set does (prefix rules: int*, str*, oid*, ip*, time*/tick*,
// opaque*; exact matches for counter32/uint32/u32, gauge32, counter64/uint64/u64).
func (d *DataSet) Set(oid string, t ValType, value any) {
	var typ uint16
	switch {
	case strings.HasPrefix(string(t), "int"):
		typ = TYPE_INTEGER
	case strings.HasPrefix(string(t), "str"):
		typ = TYPE_OCTETSTRING
	case strings.HasPrefix(string(t), "oid"):
		typ = TYPE_OBJECTIDENTIFIER
	case strings.HasPrefix(string(t), "ip"):
		typ = TYPE_IPADDRESS
	case t == ValCounter32 || t == "uint32" || t == ValU32:
		typ = TYPE_COUNTER32
		value = asUint32(value)
	case t == ValGauge32:
		typ = TYPE_GAUGE32
		value = asUint32(value)
	case strings.HasPrefix(string(t), "time") || strings.HasPrefix(string(t), "tick"):
		typ = TYPE_TIMETICKS
		value = asUint32(value)
	case strings.HasPrefix(string(t), "opaque"):
		typ = TYPE_OPAQUE
	case t == ValCounter64 || t == "uint64" || t == ValU64:
		typ = TYPE_COUNTER64
		value = asUint64(value)
	default:
		panic("agentx: invalid oid_type: " + string(t))
	}
	if d.data == nil {
		d.data = map[string]VarBind{}
	}
	d.data[oid] = VarBind{Name: oid, Type: typ, Value: value}
}

// Data returns the stored OIDs sorted by numeric arc order plus a lookup map.
func (d *DataSet) Data() ([]string, map[string]VarBind) {
	idx := make([]string, 0, len(d.data))
	for oid := range d.data {
		idx = append(idx, oid)
	}
	SortOIDs(idx)
	return idx, d.data
}

// Get returns the VarBind stored for oid and whether it exists.
func (d *DataSet) Get(oid string) (VarBind, bool) {
	v, ok := d.data[oid]
	return v, ok
}

// Len reports how many OIDs are stored.
func (d *DataSet) Len() int { return len(d.data) }

// SortOIDs sorts OIDs by tuple-of-int arc order (network.update's sort key).
func SortOIDs(oids []string) {
	sort.Slice(oids, func(i, j int) bool {
		return compareOIDs(oids[i], oids[j]) < 0
	})
}

// compareOIDs compares two dotted OIDs arc-by-arc, numerically.
func compareOIDs(a, b string) int {
	as := splitArcs(a)
	bs := splitArcs(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

func splitArcs(oid string) []uint64 {
	parts := strings.Split(oid, ".")
	out := make([]uint64, 0, len(parts))
	for _, p := range parts {
		n, _ := strconv.ParseUint(p, 10, 64)
		out = append(out, n)
	}
	return out
}
