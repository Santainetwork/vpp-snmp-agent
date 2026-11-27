package vpp

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.fd.io/govpp/adapter/statsclient"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/core"

	"github.com/santainetwork/vpp-snmp-agent/internal/mib"
)

// StatsOptions configures a StatsClient.
type StatsOptions struct {
	Socket       string
	RetryTimeout time.Duration
	Logger       *slog.Logger
}

// StatsClient reads interface counters from the VPP statseg via govpp's
// pure-Go stats client. The statsclient monitors the segment socket and
// reconnects when VPP restarts; Dump returns an error in the gap and the
// caller can call Reset to force a fresh connection.
type StatsClient struct {
	opts StatsOptions
	log  *slog.Logger

	mu     sync.Mutex
	client *statsclient.StatsClient
	conn   *core.StatsConnection
}

// NewStatsClient builds a StatsClient. It does not connect.
func NewStatsClient(opts StatsOptions) *StatsClient {
	if opts.Socket == "" {
		opts.Socket = DefaultStatsSocket
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &StatsClient{opts: opts, log: opts.Logger}
}

// Connect opens the statseg. Idempotent.
func (s *StatsClient) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectLocked()
}

func (s *StatsClient) connectLocked() error {
	if s.conn != nil {
		return nil
	}
	var clientOpts []statsclient.Option
	if s.opts.RetryTimeout > 0 {
		clientOpts = append(clientOpts, statsclient.SetSocketRetryTimeout(s.opts.RetryTimeout))
	}
	client := statsclient.NewStatsClient(s.opts.Socket, clientOpts...)
	if err := client.Connect(); err != nil {
		return fmt.Errorf("vpp: stats connect %s: %w", s.opts.Socket, err)
	}
	conn, err := core.ConnectStats(client)
	if err != nil {
		_ = client.Disconnect()
		return fmt.Errorf("vpp: stats ConnectStats: %w", err)
	}
	s.client = client
	s.conn = conn
	return nil
}

// Disconnect closes the statseg connection.
func (s *StatsClient) Disconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *StatsClient) closeLocked() {
	if s.conn != nil {
		s.conn.Disconnect()
		s.conn = nil
	}
	if s.client != nil {
		_ = s.client.Disconnect()
		s.client = nil
	}
}

// Reset drops the current statseg connection so the next Dump reconnects.
func (s *StatsClient) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

// Dump returns summed interface counters in statseg index order.
func (s *StatsClient) Dump() (*api.InterfaceStats, error) {
	s.mu.Lock()
	err := s.connectLocked()
	conn := s.conn
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := new(api.InterfaceStats)
	if err := conn.GetInterfaceStats(out); err != nil {
		return nil, fmt.Errorf("vpp: GetInterfaceStats: %w", err)
	}
	return out, nil
}

// countersFromStats converts govpp's merged view into the mib slices. Slice
// position i corresponds to sw_if_index i, the same order as /if/names.
func countersFromStats(st *api.InterfaceStats) ([]string, []mib.CounterSet, error) {
	if st == nil {
		return nil, nil, errors.New("vpp: nil interface stats")
	}
	names := make([]string, len(st.Interfaces))
	counters := make([]mib.CounterSet, len(st.Interfaces))
	for i, c := range st.Interfaces {
		names[i] = c.InterfaceName
		counters[i] = countersFromInterface(c)
	}
	return names, counters, nil
}

func countersFromInterface(c api.InterfaceCounters) mib.CounterSet {
	return mib.CounterSet{
		RXOctets:    c.Rx.Bytes,
		RXPackets:   c.Rx.Packets,
		RXMulticast: c.RxMulticast.Packets,
		RXBroadcast: c.RxBroadcast.Packets,
		RXNoBuf:     c.RxNoBuf,
		RXError:     c.RxErrors,
		RxDrops:     c.Drops,
		TXOctets:    c.Tx.Bytes,
		TXPackets:   c.Tx.Packets,
		TXMulticast: c.TxMulticast.Packets,
		TXBroadcast: c.TxBroadcast.Packets,
		TXError:     c.TxErrors,
	}
}
