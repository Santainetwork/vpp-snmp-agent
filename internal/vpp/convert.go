package vpp

import (
	"fmt"

	itf "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	lcp "go.fd.io/govpp/binapi/lcp"

	"github.com/santainetwork/vpp-snmp-agent/internal/mib"
)

func formatMAC(mac [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// ifaceFromDetails converts a generated SwInterfaceDetails into the mib type.
func ifaceFromDetails(d *itf.SwInterfaceDetails) mib.Interface {
	if d == nil {
		return mib.Interface{}
	}
	var mtus [4]uint32
	for i := 0; i < len(d.Mtu) && i < len(mtus); i++ {
		mtus[i] = d.Mtu[i]
	}
	return mib.Interface{
		SwIfIndex: uint32(d.SwIfIndex),
		Name:      d.InterfaceName,
		MTUs:      mtus,
		LinkSpeed: d.LinkSpeed,
		MAC:       formatMAC(d.L2Address),
		AdminUp:   d.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0,
		OperUp:    d.Flags&interface_types.IF_STATUS_API_FLAG_LINK_UP != 0,
	}
}

// lcpFromDetails converts a generated LcpItfPairDetails into the mib type.
func lcpFromDetails(d *lcp.LcpItfPairDetails) mib.LCPPair {
	if d == nil {
		return mib.LCPPair{}
	}
	return mib.LCPPair{
		PhySwIfIndex:  uint32(d.PhySwIfIndex),
		HostSwIfIndex: uint32(d.HostSwIfIndex),
		HostIfName:    d.HostIfName,
	}
}
