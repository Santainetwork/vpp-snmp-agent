package mib

import (
	"fmt"
	"strings"

	"github.com/santainetwork/vpp-snmp-agent/internal/agentx"
)

// ifTableRow sets the ifTable subtree varbinds for one interface.
// Column numbering follows RFC 2863 (ifTable).
func ifTable(ds *agentx.DataSet, ifname string, idx, pos int, s Snapshot) {
	c := s.Counters[pos]
	iface, haveIface := s.Ifaces[ifname]

	ds.Set(fmt.Sprintf("%s.1.%d", ifTableRoot, idx), "int", int64(idx))

	// ifName with LCP remapping (ifAlias lives in ifXTable only)
	ifName := ifname
	if strings.HasPrefix(ifname, "tap") && haveIface {
		if hostIfName, _, ok := lcpByHostSwIf(s, iface.SwIfIndex); ok {
			ifName = hostIfName
		}
	}
	ds.Set(fmt.Sprintf("%s.2.%d", ifTableRoot, idx), "str", ifName)

	ifType := int64(6) // ethernetCsmacd
	if strings.HasPrefix(ifname, "loop") {
		ifType = 24 // softwareLoopback
	}
	ds.Set(fmt.Sprintf("%s.3.%d", ifTableRoot, idx), "int", ifType)

	mtu := uint32(0)
	if haveIface {
		mtu = iface.MTUs[0]
	}
	ds.Set(fmt.Sprintf("%s.4.%d", ifTableRoot, idx), "int", int64(mtu))

	speed := uint64(0)
	switch {
	case strings.HasPrefix(ifname, "loop") || strings.HasPrefix(ifname, "tap"):
		speed = 1_000_000_000
	case haveIface:
		speed = uint64(iface.LinkSpeed) * 1000
	}
	ds.Set(fmt.Sprintf("%s.5.%d", ifTableRoot, idx), "gauge32", u32(speed))

	ds.Set(fmt.Sprintf("%s.6.%d", ifTableRoot, idx), "str", macOrZeros(iface.MAC))

	// adminStatus / operStatus
	admin := int64(3) // testing
	if haveIface && iface.AdminUp {
		admin = 1
	} else if haveIface {
		admin = 2
	}
	oper := int64(3)
	if haveIface && iface.OperUp {
		oper = 1
	} else if haveIface {
		oper = 2
	}
	ds.Set(fmt.Sprintf("%s.7.%d", ifTableRoot, idx), "int", admin)
	ds.Set(fmt.Sprintf("%s.8.%d", ifTableRoot, idx), "int", oper)

	ds.Set(fmt.Sprintf("%s.9.%d", ifTableRoot, idx), "ticks", int64(0))

	ds.Set(fmt.Sprintf("%s.10.%d", ifTableRoot, idx), "u32", u32(c.RXOctets))
	ds.Set(fmt.Sprintf("%s.11.%d", ifTableRoot, idx), "u32", u32(c.RXPackets))
	ds.Set(fmt.Sprintf("%s.12.%d", ifTableRoot, idx), "u32", u32(c.RXMulticast))
	ds.Set(fmt.Sprintf("%s.13.%d", ifTableRoot, idx), "u32", u32(c.RXNoBuf))
	ds.Set(fmt.Sprintf("%s.14.%d", ifTableRoot, idx), "u32", u32(c.RXError))
	// 15 = ifInUnknownProtos (not collected)
	ds.Set(fmt.Sprintf("%s.16.%d", ifTableRoot, idx), "u32", u32(c.TXOctets))
	ds.Set(fmt.Sprintf("%s.17.%d", ifTableRoot, idx), "u32", u32(c.TXPackets))
	ds.Set(fmt.Sprintf("%s.18.%d", ifTableRoot, idx), "u32", u32(c.TXMulticast))
	ds.Set(fmt.Sprintf("%s.19.%d", ifTableRoot, idx), "u32", u32(c.RxDrops))
	ds.Set(fmt.Sprintf("%s.20.%d", ifTableRoot, idx), "u32", u32(c.TXError))
}

// ifXTableRow sets ifXTable subtree. Column numbering follows RFC 2863.
func ifXTable(ds *agentx.DataSet, ifname string, idx, pos int, s Snapshot) {
	c := s.Counters[pos]
	iface, haveIface := s.Ifaces[ifname]

	ifName := ifname
	ifAlias := ""
	if strings.HasPrefix(ifname, "tap") && haveIface {
		if hostIfName, phyName, ok := lcpByHostSwIf(s, iface.SwIfIndex); ok {
			ifName = hostIfName
			if phyName != "" {
				ifAlias = fmt.Sprintf("LCP %s (%s)", phyName, ifname)
			}
		}
	}
	ds.Set(fmt.Sprintf("%s.1.%d", ifXTableRoot, idx), "str", ifName)
	ds.Set(fmt.Sprintf("%s.2.%d", ifXTableRoot, idx), "u32", u32(c.RXMulticast))
	ds.Set(fmt.Sprintf("%s.3.%d", ifXTableRoot, idx), "u32", u32(c.RXBroadcast))
	ds.Set(fmt.Sprintf("%s.4.%d", ifXTableRoot, idx), "u32", u32(c.TXMulticast))
	ds.Set(fmt.Sprintf("%s.5.%d", ifXTableRoot, idx), "u32", u32(c.TXBroadcast))
	ds.Set(fmt.Sprintf("%s.6.%d", ifXTableRoot, idx), "u64", c.RXOctets)
	ds.Set(fmt.Sprintf("%s.7.%d", ifXTableRoot, idx), "u64", c.RXPackets)
	ds.Set(fmt.Sprintf("%s.8.%d", ifXTableRoot, idx), "u64", c.RXMulticast)
	ds.Set(fmt.Sprintf("%s.9.%d", ifXTableRoot, idx), "u64", c.RXBroadcast)
	ds.Set(fmt.Sprintf("%s.10.%d", ifXTableRoot, idx), "u64", c.TXOctets)
	ds.Set(fmt.Sprintf("%s.11.%d", ifXTableRoot, idx), "u64", c.TXPackets)
	ds.Set(fmt.Sprintf("%s.12.%d", ifXTableRoot, idx), "u64", c.TXMulticast)
	ds.Set(fmt.Sprintf("%s.13.%d", ifXTableRoot, idx), "u64", c.TXBroadcast)

	speedKbps := uint64(0)
	switch {
	case strings.HasPrefix(ifname, "loop") || strings.HasPrefix(ifname, "tap"):
		speedKbps = 1000
	case haveIface:
		speedKbps = uint64(iface.LinkSpeed)
	}
	ds.Set(fmt.Sprintf("%s.15.%d", ifXTableRoot, idx), "gauge32", u32(speedKbps))

	// 16 = linkUpDownTrapEnable = 2 (false), 17 = highSpeed legacy = 1
	ds.Set(fmt.Sprintf("%s.16.%d", ifXTableRoot, idx), "int", int64(2))
	ds.Set(fmt.Sprintf("%s.17.%d", ifXTableRoot, idx), "int", int64(1))

	if ifAlias == "" {
		if d := s.Config.Description(ifname); d != "" {
			ifAlias = d
		}
	}
	if ifAlias == "" {
		ifAlias = ifname
	}
	ds.Set(fmt.Sprintf("%s.18.%d", ifXTableRoot, idx), "str", ifAlias)
	ds.Set(fmt.Sprintf("%s.19.%d", ifXTableRoot, idx), "ticks", int64(0))
}
