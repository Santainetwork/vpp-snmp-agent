package agentx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// NetworkError is returned when the AgentX connection breaks mid-operation.
var NetworkError = errors.New("agentx: network error")

// Network is the port of class Network in network.py: one AgentX session over
// a TCP or Unix socket, holding the currently served dataset.
type Network struct {
	SessionID     uint32
	TransactionID uint32
	Debug         bool

	mu          sync.RWMutex
	data        map[string]VarBind
	dataIdx     []string
	connected   bool
	conn        net.Conn
	serverAddr  string
	pollTimeout time.Duration
}

// NewNetwork returns an idle Network for serverAddress (a "host:port" for TCP
// or an absolute path for a Unix socket).
func NewNetwork(serverAddress string, debug bool) *Network {
	return &Network{
		Debug:       debug,
		serverAddr:  serverAddress,
		pollTimeout: 100 * time.Millisecond,
	}
}

// Connect opens the socket if not already connected, mirroring Network.connect.
// It returns an error instead of swallowing socket errors.
func (n *Network) Connect() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.connected {
		return nil
	}
	var (
		conn net.Conn
		err  error
	)
	if strings.HasPrefix(n.serverAddr, "/") {
		conn, err = net.Dial("unix", n.serverAddr)
	} else {
		conn, err = net.Dial("tcp", n.serverAddr)
	}
	if err != nil {
		n.connected = false
		return fmt.Errorf("agentx: connect to %s: %w", n.serverAddr, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(n.pollTimeout))
	n.conn = conn
	n.connected = true
	return nil
}

// Disconnect closes the socket, mirroring Network.disconnect.
func (n *Network) Disconnect() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.connected {
		return
	}
	_ = n.conn.Close()
	n.conn = nil
	n.connected = false
}

// IsConnected reports whether the socket is currently open.
func (n *Network) IsConnected() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.connected
}

// Update swaps the served dataset atomically (Network.update). The sorted index
// is recomputed with numeric arc ordering.
func (n *Network) Update(data map[string]VarBind) {
	idx := make([]string, 0, len(data))
	for oid := range data {
		idx = append(idx, oid)
	}
	SortOIDs(idx)
	n.mu.Lock()
	n.data = data
	n.dataIdx = idx
	n.mu.Unlock()
}

// snapshot returns a consistent view of the served data and index.
func (n *Network) snapshot() (map[string]VarBind, []string) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.data, n.dataIdx
}

// newPDU mirrors Network.new_pdu: stamp session/transaction ids and bump the
// transaction counter.
func (n *Network) newPDU(typ uint32) *PDU {
	p := &PDU{Type: typ, SessionID: n.SessionID, TransactionID: n.TransactionID}
	n.TransactionID++
	return p
}

// responsePDU mirrors Network.response_pdu.
func (n *Network) responsePDU(org *PDU) *PDU {
	return &PDU{Type: PDU_RESPONSE, SessionID: org.SessionID, TransactionID: org.TransactionID, PacketID: org.PacketID}
}

// sendPDU writes the encoded PDU to the socket.
func (n *Network) sendPDU(p *PDU) error {
	if n.Debug {
		log.Printf("[agentx] send type=%d session=%d tx=%d packet=%d", p.Type, p.SessionID, p.TransactionID, p.PacketID)
	}
	buf := p.Encode()
	_, err := n.conn.Write(buf)
	return err
}

// recvPDU reads exactly one PDU (header + payload) using the socket deadline.
func (n *Network) recvPDU(deadline time.Time) (*PDU, error) {
	if err := n.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	header := make([]byte, 20)
	if _, err := io.ReadFull(n.conn, header); err != nil {
		return nil, err
	}
	if n.Debug {
		log.Printf("[agentx] recv header %x", header)
	}
	nPayload := binary.BigEndian.Uint32(header[16:])
	payload := make([]byte, nPayload)
	if _, err := io.ReadFull(n.conn, payload); err != nil {
		return nil, err
	}
	return DecodePDU(append(header, payload...))
}

// Start mirrors Network.start: OPEN, PING, then one REGISTER per OID, reading
// each response.
func (n *Network) Start(oidList []string) error {
	if err := n.Connect(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)

	p := n.newPDU(PDU_OPEN)
	if err := n.sendPDU(p); err != nil {
		return err
	}
	resp, err := n.recvPDU(deadline)
	if err != nil {
		return err
	}
	n.SessionID = resp.SessionID

	p = n.newPDU(PDU_PING)
	if err := n.sendPDU(p); err != nil {
		return err
	}
	if _, err := n.recvPDU(deadline); err != nil {
		return err
	}

	for _, oid := range oidList {
		p = n.newPDU(PDU_REGISTER)
		p.OID = oid
		if err := n.sendPDU(p); err != nil {
			return err
		}
		if _, err := n.recvPDU(deadline); err != nil {
			return err
		}
	}
	return nil
}

// Run mirrors Network.run: poll for one request, answer GET/GETNEXT from the
// served dataset. It returns nil on read timeout and an error wrapping
// NetworkError when the connection breaks.
func (n *Network) Run(timeout time.Duration) error {
	if !n.IsConnected() {
		return NetworkError
	}
	request, err := n.recvPDU(time.Now().Add(timeout))
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		n.Disconnect()
		return fmt.Errorf("%w: %v", NetworkError, err)
	}
	response := n.responsePDU(request)
	switch request.Type {
	case PDU_GET:
		data, _ := n.snapshot()
		for _, r := range request.RangeList {
			if v, ok := data[r.StartOID]; ok {
				response.Values = append(response.Values, v)
			} else {
				response.Values = append(response.Values, VarBind{Type: TYPE_NOSUCHOBJECT, Name: r.StartOID, Value: uint32(0)})
			}
		}
	case PDU_GETNEXT:
		data, idx := n.snapshot()
		for _, r := range request.RangeList {
			oid := getNextOID(idx, data, r.StartOID, r.EndOID)
			if oid != "" {
				response.Values = append(response.Values, data[oid])
			} else {
				response.Values = append(response.Values, VarBind{Type: TYPE_ENDOFMIBVIEW, Name: r.StartOID, Value: uint32(0)})
			}
		}
	default:
		if n.Debug {
			log.Printf("[agentx] unsupported PDU type %d", request.Type)
		}
	}
	if err := n.sendPDU(response); err != nil {
		n.Disconnect()
		return fmt.Errorf("%w: %v", NetworkError, err)
	}
	return nil
}

// getNextOID is the port of Network._get_next_oid. Exact match returns the next
// sorted OID; otherwise it walks the sorted index for the first OID whose arcs
// fall between start and end.
func getNextOID(idx []string, data map[string]VarBind, oid, endOID string) string {
	if _, ok := data[oid]; ok {
		for i, candidate := range idx {
			if candidate == oid {
				if i == len(idx)-1 {
					return ""
				}
				return idx[i+1]
			}
		}
		return ""
	}
	startArcs := splitArcs(oid)
	endArcs := splitArcs(endOID)
	for _, candidate := range idx {
		cArcs := splitArcs(candidate)
		match := true
		for i := range cArcs {
			if i < len(startArcs) && startArcs[i] > cArcs[i] {
				match = false
				break
			}
			if i < len(endArcs) && endArcs[i] < cArcs[i] {
				match = false
				break
			}
		}
		if match {
			return candidate
		}
	}
	return ""
}

// Stop closes the connection (Network.stop).
func (n *Network) Stop() { n.Disconnect() }
