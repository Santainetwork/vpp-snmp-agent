package vpp

import (
	"testing"

	"go.fd.io/govpp/api"
	itf "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	lcp "go.fd.io/govpp/binapi/lcp"

	"github.com/santainetwork/vpp-snmp-agent/internal/mib"
)

func TestIfaceFromDetails(t *testing.T) {
	d := &itf.SwInterfaceDetails{
		SwIfIndex:     interface_types.InterfaceIndex(7),
		InterfaceName: "eth0",
		LinkSpeed:     2500000,
		Mtu:           []uint32{1500, 1492, 1400, 1300},
		L2Address:     [6]byte{0, 1, 2, 0xaa, 0xbb, 0xff},
		Flags:         interface_types.IF_STATUS_API_FLAG_ADMIN_UP | interface_types.IF_STATUS_API_FLAG_LINK_UP,
	}
	got := ifaceFromDetails(d)
	if got.SwIfIndex != 7 || got.Name != "eth0" || got.LinkSpeed != 2500000 {
		t.Fatalf("identity fields wrong: %+v", got)
	}
	if got.MTUs != [4]uint32{1500, 1492, 1400, 1300} || got.MAC != "00:01:02:aa:bb:ff" {
		t.Fatalf("MTU/MAC wrong: %+v", got)
	}
	if !got.AdminUp || !got.OperUp {
		t.Fatalf("flags not mapped: %+v", got)
	}
}

func TestIfaceFromDetailsShortMTU(t *testing.T) {
	got := ifaceFromDetails(&itf.SwInterfaceDetails{Mtu: []uint32{9000}})
	if got.MTUs != [4]uint32{9000, 0, 0, 0} {
		t.Fatalf("short MTU mapping wrong: %v", got.MTUs)
	}
}

func TestLCPFromDetails(t *testing.T) {
	got := lcpFromDetails(&lcp.LcpItfPairDetails{
		PhySwIfIndex: 3, HostSwIfIndex: 9, HostIfName: "vpp0",
	})
	if got.PhySwIfIndex != 3 || got.HostSwIfIndex != 9 || got.HostIfName != "vpp0" {
		t.Fatalf("LCP mapping wrong: %+v", got)
	}
}

func TestCountersFromStats(t *testing.T) {
	st := &api.InterfaceStats{Interfaces: []api.InterfaceCounters{{
		InterfaceIndex: 0, InterfaceName: "eth0",
		Rx:          api.InterfaceCounterCombined{Packets: 4, Bytes: 40},
		Tx:          api.InterfaceCounterCombined{Packets: 5, Bytes: 50},
		RxMulticast: api.InterfaceCounterCombined{Packets: 6},
		RxBroadcast: api.InterfaceCounterCombined{Packets: 7},
		RxNoBuf:     8, RxErrors: 9, Drops: 10,
		TxMulticast: api.InterfaceCounterCombined{Packets: 11},
		TxBroadcast: api.InterfaceCounterCombined{Packets: 12}, TxErrors: 13,
	}}}
	names, counters, err := countersFromStats(st)
	if err != nil {
		t.Fatal(err)
	}
	want := mib.CounterSet{
		RXOctets: 40, RXPackets: 4, RXMulticast: 6, RXBroadcast: 7,
		RXNoBuf: 8, RXError: 9, RxDrops: 10, TXOctets: 50, TXPackets: 5,
		TXMulticast: 11, TXBroadcast: 12, TXError: 13,
	}
	if len(names) != 1 || names[0] != "eth0" || len(counters) != 1 || counters[0] != want {
		t.Fatalf("counter conversion mismatch: names=%v counters=%+v", names, counters)
	}
}
