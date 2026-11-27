package vpp

import (
	"encoding/hex"
	"fmt"

	itf "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	lcp "go.fd.io/govpp/binapi/lcp"
)

// Interface mirrors the fields the Python agent read from sw_interface_details.
type Interface struct {
	SwIfIndex uint32
	Name      string
	// LinkSpeed is in kbps (raw link_speed from VPP).
	LinkSpeed uint32
	// MTU is the L3 MTU (first entry of mtu[4]).
	MTU uint32
	// MAC is the formatted colon-separated hardware address.
	MAC string
	// AdminState / OperState are bools derived from if_status_flags bit 0/1.
	AdminState bool
	OperState  bool
	Type       string
	Flags      uint32
}

// LCPPair mirrors lcp_itf_pair_details.
type LCPPair struct {
	PhySwIfIndex  uint32
	HostSwIfIndex uint32
	VifIndex      uint32
	HostIfName    string
	HostIfType    string
	Netns         string
}

func formatMAC(mac [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// newInterfaceFromDetails converts a govpp-generated SwInterfaceDetails into
// the public Interface struct.
func newInterfaceFromDetails(d *itf.SwInterfaceDetails) Interface {
	if d == nil {
		return Interface{}
	}
	var mtu uint32
	if len(d.Mtu) > 0 {
		mtu = d.Mtu[0]
	}
	return Interface{
		SwIfIndex:  uint32(d.SwIfIndex),
		Name:       d.InterfaceName,
		LinkSpeed:  d.LinkSpeed,
		MTU:        mtu,
		MAC:        formatMAC(d.L2Address),
		AdminState: d.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0,
		OperState:  d.Flags&interface_types.IF_STATUS_API_FLAG_LINK_UP != 0,
		Type:       d.InterfaceDevType,
		Flags:      uint32(d.Flags),
	}
}

// newLCPPairFromDetails converts a govpp-generated LcpItfPairDetails.
func newLCPPairFromDetails(d *lcp.LcpItfPairDetails) LCPPair {
	if d == nil {
		return LCPPair{}
	}
	return LCPPair{
		PhySwIfIndex:  uint32(d.PhySwIfIndex),
		HostSwIfIndex: uint32(d.HostSwIfIndex),
		VifIndex:      d.VifIndex,
		HostIfName:    d.HostIfName,
		HostIfType:    d.HostIfType.String(),
		Netns:         d.Netns,
	}
}

