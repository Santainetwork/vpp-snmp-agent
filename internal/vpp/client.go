// Package vpp implements VPP binary-API inventory and stats-segment counters
// on top of govpp (snapshot c02eb51f8588, module go.fd.io/govpp).
//
// Compatibility: interface data comes from the generated binapi bindings
// (binapi/interface SwInterfaceDetails CRC 6c221fc7, binapi/lcp
// LcpItfPairDetails CRC 8b5481af). govpp resolves message CRCs at Connect
// time, so a VPP release that drops or changes a message surfaces as a
// VPPApiError; we never hand-encode API messages. LCP is optional: if the
// plugin is absent, LCPPairs returns an empty map.
//
// Counters are read through adapter/statsclient, the pure-Go stats client that
// speaks statseg v1 and v2. No manual mmap. Per-worker vectors are summed to a
// single per-interface value, matching the Python agent's [:, i].sum() use.
package vpp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"go.fd.io/govpp/adapter/socketclient"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/core"

	itf "go.fd.io/govpp/binapi/interface"
	lcp "go.fd.io/govpp/binapi/lcp"

	"github.com/santainetwork/vpp-snmp-agent/internal/mib"
)

const (
	// DefaultAPISocket is the VPP binary API socket.
	DefaultAPISocket = "/run/vpp/api.sock"
	// DefaultStatsSocket is the VPP stats segment socket.
	DefaultStatsSocket = "/run/vpp/stats.sock"
	// DefaultTimeout bounds every RPC when the caller's context has no deadline.
	DefaultTimeout = 5 * time.Second
)

// ErrNotConnected is returned when an operation needs a live VPP connection.
var ErrNotConnected = errors.New("vpp: not connected")

// Options configures a Client.
type Options struct {
	Logger      *slog.Logger
	PollPeriod  time.Duration
	Socket      string
	StatsSocket string
	Timeout     time.Duration
}

// Client owns the binary API connection plus the stats segment connection.
type Client struct {
	opts Options
	log  *slog.Logger

	mu     sync.Mutex
	conn   *core.Connection
	closed bool

	stats *StatsClient
}

// NewClient builds a Client. It does not connect.
func NewClient(opts Options) *Client {
	if opts.Socket == "" {
		opts.Socket = DefaultAPISocket
	}
	if opts.StatsSocket == "" {
		opts.StatsSocket = DefaultStatsSocket
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	c := &Client{opts: opts, log: opts.Logger}
	if opts.PollPeriod > 0 {
		retry := opts.PollPeriod
		if retry > 3*time.Second {
			retry = 3 * time.Second
		}
		c.stats = NewStatsClient(StatsOptions{
			Socket:       opts.StatsSocket,
			RetryTimeout: retry,
			Logger:       opts.Logger,
		})
	} else {
		c.stats = NewStatsClient(StatsOptions{
			Socket: opts.StatsSocket,
			Logger: opts.Logger,
		})
	}
	return c
}

// Connect opens the binary API and stats connections. Idempotent.
func (c *Client) Connect(ctx context.Context) error {
	if err := c.connectAPI(ctx); err != nil {
		return err
	}
	if err := c.stats.Connect(); err != nil {
		c.log.Warn("vpp stats connect failed; counters unavailable until reconnect", "err", err)
	}
	return nil
}

func (c *Client) connectAPI(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	if c.closed {
		return errors.New("vpp: client closed")
	}
	conn, err := core.Connect(socketclient.NewVppClient(c.opts.Socket))
	if err != nil {
		return fmt.Errorf("vpp: connect %s: %w", c.opts.Socket, err)
	}
	c.conn = conn

	// Best effort: ask VPP to publish sw_interface_event notifications so a
	// future cache layer can invalidate cheaply. Failure is not fatal.
	rpcCtx, cancel := context.WithTimeout(detach(ctx), c.opts.Timeout)
	defer cancel()
	var w itf.WantInterfaceEvents
	w.EnableDisable = 1
	var wr itf.WantInterfaceEventsReply
	if err := conn.Invoke(rpcCtx, &w, &wr); err != nil {
		c.log.Debug("vpp: want_interface_events failed", "err", err)
	}
	return nil
}

// Disconnect closes both connections.
func (c *Client) Disconnect() {
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Disconnect()
		c.conn = nil
	}
	c.closed = true
	c.mu.Unlock()
	c.stats.Disconnect()
}

// Interfaces returns the interface inventory keyed by VPP interface name.
func (c *Client) Interfaces(ctx context.Context) (map[string]mib.Interface, error) {
	out := make(map[string]mib.Interface)
	err := c.withConn(ctx, func(conn *core.Connection, rpcCtx context.Context) error {
		svc := itf.NewServiceClient(conn)
		stream, err := svc.SwInterfaceDump(rpcCtx, &itf.SwInterfaceDump{
			SwIfIndex: interface_types.InterfaceIndex(0xFFFFFFFF), // ~0 = all
		})
		if err != nil {
			return fmt.Errorf("sw_interface_dump: %w", err)
		}
		for {
			d, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("sw_interface_dump recv: %w", err)
			}
			iface := ifaceFromDetails(d)
			out[iface.Name] = iface
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LCPPairs returns Linux Control Plane pairs keyed by host_if_name. When the
// lcp plugin is not loaded (message unknown or call fails), it returns an
// empty map and a nil error so base interface inventory is never blocked.
func (c *Client) LCPPairs(ctx context.Context) (map[string]mib.LCPPair, error) {
	out := make(map[string]mib.LCPPair)
	err := c.withConn(ctx, func(conn *core.Connection, rpcCtx context.Context) error {
		svc := lcp.NewServiceClient(conn)
		stream, err := svc.LcpItfPairGet(rpcCtx, &lcp.LcpItfPairGet{})
		if err != nil {
			return err
		}
		for {
			d, _, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			p := lcpFromDetails(d)
			out[p.HostIfName] = p
		}
	})
	if err != nil {
		// Plugin missing or incompatible schema: report no pairs, keep going.
		c.log.Debug("vpp: LCP pairs unavailable", "err", err)
		return map[string]mib.LCPPair{}, nil
	}
	return out, nil
}

// InterfaceCounters returns interface names in statseg /if/names order and a
// matching slice of summed counters. Retries once after reconnecting the stats
// client if the segment dropped.
func (c *Client) InterfaceCounters(ctx context.Context) ([]string, []mib.CounterSet, error) {
	st, err := c.stats.Dump()
	if err != nil {
		c.log.Debug("vpp: stats dump failed, reconnecting", "err", err)
		c.stats.Reset()
		st, err = c.stats.Dump()
		if err != nil {
			return nil, nil, err
		}
	}
	return countersFromStats(st)
}

// withConn runs fn against a live connection, reconnecting once if govpp
// reports the connection dropped mid-call.
func (c *Client) withConn(ctx context.Context, fn func(*core.Connection, context.Context) error) error {
	conn, err := c.connection(ctx)
	if err != nil {
		return err
	}
	rpcCtx, cancel := context.WithTimeout(detach(ctx), c.opts.Timeout)
	defer cancel()
	err = fn(conn, rpcCtx)
	if err == nil {
		return nil
	}
	if !isConnError(err) {
		return err
	}
	// Force a fresh connection and retry once.
	c.mu.Lock()
	if c.conn == conn {
		conn.Disconnect()
		c.conn = nil
	}
	c.mu.Unlock()
	if cerr := c.connectAPI(ctx); cerr != nil {
		return fmt.Errorf("%w (reconnect: %v)", err, cerr)
	}
	conn, err2 := c.connection(ctx)
	if err2 != nil {
		return err2
	}
	rpcCtx2, cancel2 := context.WithTimeout(detach(ctx), c.opts.Timeout)
	defer cancel2()
	return fn(conn, rpcCtx2)
}

func (c *Client) connection(ctx context.Context) (*core.Connection, error) {
	c.mu.Lock()
	conn, closed := c.conn, c.closed
	c.mu.Unlock()
	if conn == nil && !closed {
		if err := c.connectAPI(ctx); err != nil {
			return nil, err
		}
		c.mu.Lock()
		conn = c.conn
		c.mu.Unlock()
	}
	if conn == nil {
		return nil, core.ErrNotConnected
	}
	return conn, nil
}

// isConnError reports whether err indicates a broken transport rather than a
// VPP semantic error, so retrying after reconnect is worthwhile.
func isConnError(err error) bool {
	if errors.Is(err, core.ErrNotConnected) {
		return true
	}
	var vppErr api.VPPApiError
	if errors.As(err, &vppErr) {
		return false
	}
	return true
}

// detach returns ctx if it has a deadline, else context.Background() so the
// caller's timeout wrapper controls cancellation.
func detach(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
