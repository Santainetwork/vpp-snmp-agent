// Package mib builds the IF-MIB dataset from VPP inventory + counters, matching the
// original Python vpp-snmp-agent behaviour (ifTable + ifXTable).
package mib

import (
	"math"

	"github.com/santainetwork/vpp-snmp-agent/internal/agentx"
)

const (
	ifTableRoot  = "1.3.6.1.2.1.2.2.1"
	ifXTableRoot = "1.3.6.1.2.1.31.1.1.1"
	// ifIndexOffset matches Python: index = 1000 + position in /if/names vector
	ifIndexOffset = 1000
)

// Interface is the subset of VPP interface metadata the MIB needs.
type Interface struct {
	SwIfIndex uint32
	Name      string
	// MTUs is ordered [L3, IP4, IP6, MPLS]; Python uses MTUs[0]
	MTUs      [4]uint32
	LinkSpeed uint32 // kbps
	MAC       string // aa:bb:cc:dd:ee:ff
	AdminUp   bool
	OperUp    bool
}

// LCPPair mirrors lcp_itf_pair_details: host tap <-> phy.
type LCPPair struct {
	PhySwIfIndex  uint32
	HostSwIfIndex uint32
	HostIfName    string
}

// CounterSet holds summed-thread counters for one interface (position in Names).
type CounterSet struct {
	RXOctets, RXPackets      uint64
	RXMulticast, RXBroadcast uint64
	RXNoBuf, RXError, RxDrops uint64
	TXOctets, TXPackets      uint64
	TXMulticast, TXBroadcast uint64
	TXError                  uint64
}

// Snapshot is the input to Build: everything needed to render one IF-MIB update.
type Snapshot struct {
	Names     []string
	Counters  []CounterSet
	Ifaces    map[string]Interface
	LCPPairs  map[string]LCPPair
	Config    Config
}

func u32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

func macOrZeros(s string) string {
	if s == "" {
		return "00:00:00:00:00:00"
	}
	return s
}

// Build renders the full IF-MIB varbind set for the snapshot.
func Build(s Snapshot) *agentx.DataSet {
	ds := agentx.NewDataSet()
	for i, ifname := range s.Names {
		idx := ifIndexOffset + i
		ifTable(ds, ifname, idx, i, s)
		ifXTable(ds, ifname, idx, i, s)
	}
	return ds
}

func ifaceBySwIf(s Snapshot, idx uint32) (Interface, bool) {
	for _, v := range s.Ifaces {
		if v.SwIfIndex == idx {
			return v, true
		}
	}
	return Interface{}, false
}

func lcpByHostSwIf(s Snapshot, hostSwIfIdx uint32) (hostIfName, phyName string, ok bool) {
	for _, p := range s.LCPPairs {
		if p.HostSwIfIndex == hostSwIfIdx {
			hostIfName = p.HostIfName
			if phy, found := ifaceBySwIf(s, p.PhySwIfIndex); found {
				phyName = phy.Name
			}
			return hostIfName, phyName, true
		}
	}
	return "", "", false
}
