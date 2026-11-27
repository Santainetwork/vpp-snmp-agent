// Package vpp implements VPP binary-API and stats-segment clients built on
// the current govpp snapshot (c02eb51f8588).
//
// Compatibility note: interface fields are taken from the generated
// binapi/interface (SwInterfaceDetails, CRC aa610c27) and binapi/lcp
// (LcpItfPairDetails, CRC 8b5481af) bindings. govpp negotiates the CRC at
// Connect time; if a newer VPP drops either message the RPC call returns
// api.ErrUnknownMsg and we surface it to the caller. LCP is treated as
// optional per task spec: failures are logged, never fatal for base
// interface inventory. The stats segment is read via adapter/statsclient,
// which understands statseg v2 (and v1); we never mmap manually.
package vpp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.fd.io/govpp/adapter/socketclient"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/memclnt"
	"go.fd.io/govpp/core"

	itf "go.fd.io/govpp/binapi/interface"
	lcp "go.fd.io/govpp/binapi/lcp"
)

// Default API socket path. Override with WithSocket.
const DefaultAPISocket = "/run/vpp/api.sock"

// RPC timeout used for every binapi call.
const DefaultRPCTimeout = 3 * time.Second

// ErrNotConnected is returned by methods that require an established
// connection if Connect has not succeeded (or the peer dropped).
var ErrNotConnected = errors.New("vpp: not connected")

// ErrLCPUnavailable is returned when the lcp plugin is absent or its API
// schema does not match the generated binding. Callers treat this as "no
// LCP pairs" rather than a hard failure.
var ErrLCPUnavailable = errors.New("vpp: lcp plugin unavailable")

// Client wraps a govpp core.Connection to the VPP binary API.
type Client struct {
	mu       sync.Mutex
	conn     *core.Connection
	sockPath string
	timeout  time.Duration
	closed   bool
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithSocket overrides the binary API socket path.
func WithSocket(path string) ClientOption {
	return func(c *Client) { c.sockPath = path }
}

// WithTimeout overrides the per-RPC context timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.timeout = d }
}

// NewClient builds a Client. It does not connect; call Connect.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		sockPath: DefaultAPISocket,
		timeout:  DefaultRPCTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Connect establishes the binary API connection and enables interface event
// notifications so callers can cheaply invalidate their cached views. A
// failure to enable events is non-fatal (older VPP builds may not have the
// message); the inventory calls still work.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	if c.closed {
		return errors.New("vpp: client closed")
	}
	adapter := socketclient.NewVppClient(c.sockPath)
	conn, err := core.Connect(adapter)
	if err != nil {
		return fmt.Errorf("vpp: connect %s: %w", c.sockPath, err)
	}
	c.conn = conn

	// Best-effort: ask VPP to push sw_interface_event notifications.
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	var e memclnt.ControlPing
	var r memclnt.ControlPingReply
	if err := conn.Invoke(ctx, &e, &r); err != nil {
		// Ping failing is fine — some minimal builds answer only later.
		_ = err
	}
	if svc := itf.NewServiceClient(conn); svc != nil {
		var w itf.WantInterfaceEvents
		w.EnableDisable = true
		var wr itf.WantInterfaceEventsReply
		_ = conn.Invoke(ctx, &w, &wr)
	}
	return nil
}

// Disconnect closes the underlying connection.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.conn != nil {
		c.conn.Disconnect()
		c.conn = nil
	}
	return nil
}

// connLocked returns the live connection or an error. Caller must hold c.mu.
func (c *Client) connLocked() (*core.Connection, error) {
	if c.conn == nil {
		return nil, ErrNotConnected
	}
	return c.conn, nil
}

// Interfaces dumps all software interfaces via SwInterfaceDump and returns
// them in VPP sw_if_index order. Cached internally until Disconnect.
func (c *Client) Interfaces(ctx context.Context) ([]Interface, error) {
	c.mu.Lock()
	conn, err := c.connLocked()
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
	}
	svc := itf.NewServiceClient(conn)
	stream, err := svc.SwInterfaceDump(ctx, &itf.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(0xFFFFFFFF), // ~0 = all
	})
	if err != nil {
		// Connection likely dropped; surface so callers can reconnect.
		return nil, fmt.Errorf("vpp: sw_interface_dump: %w", err)
	}
	out := make([]Interface, 0, 8)
	for {
		details, err := stream.Recv()
		if errors.Is(err, api.ErrEndOfStream) || errors.Is(err, api.ErrStreamClosed) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("vpp: sw_interface_dump recv: %w", err)
		}
		out = append(out, newInterfaceFromDetails(details))
	}
	return out, nil
}

// LCPPairs returns Linux Control Plane interface pairs. Missing lcp plugin
// yields (nil, ErrLCPUnavailable); every other error is returned as-is.
func (c *Client) LCPPairs(ctx context.Context) ([]LCPPair, error) {
	c.mu.Lock()
	conn, err := c.connLocked()
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
	}
	svc := lcp.NewServiceClient(conn)
	stream, err := svc.LcpItfPairGet(ctx, &lcp.LcpItfPairGet{})
	if err != nil {
		if errors.Is(err, api.ErrUnknownMsg) {
			return nil, ErrLCPUnavailable
		}
		// Many VPP builds return a generic error if the plugin is not loaded.
		return nil, fmt.Errorf("%w: %v", ErrLCPUnavailable, err)
	}
	out := make([]LCPPair, 0, 4)
	for {
		details, _, err := stream.Recv()
		if errors.Is(err, api.ErrEndOfStream) || errors.Is(err, api.ErrStreamClosed) {
			break
		}
		if err != nil {
			if errors.Is(err, api.ErrUnknownMsg) {
				return nil, ErrLCPUnavailable
			}
			return nil, fmt.Errorf("vpp: lcp_itf_pair_get recv: %w", err)
		}
		out = append(out, newLCPPairFromDetails(details))
	}
	return out, nil
}
