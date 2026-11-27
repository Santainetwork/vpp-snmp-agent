// Package app wires the AgentX server, VPP inventory/stats collectors and the
// IF-MIB renderer into the long-running poll loop that replaced the Python daemon.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/santainetwork/vpp-snmp-agent/internal/agentx"
	"github.com/santainetwork/vpp-snmp-agent/internal/mib"
	"github.com/santainetwork/vpp-snmp-agent/internal/vpp"
)

// Options configures a new App.
type Options struct {
	AgentAddress string        // snmpd AgentX socket: "localhost:705" or "/var/agentx/master"
	PollPeriod   time.Duration // VPP re-poll interval
	ConfigPath   string        // optional vppcfg YAML
	Debug        bool          // verbose logging
	AgentXDebug  bool          // PDU-level logging
}

const (
	ifTableOID  = "1.3.6.1.2.1.2.2.1"
	ifXTableOID = "1.3.6.1.2.1.31.1.1.1"
)

type App struct {
	opts   Options
	log    *slog.Logger
	cfg    mib.Config
	vpp    *vpp.Client
	agent  *agentx.Agent
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates the app: loads YAML, connects to VPP API + statseg, prepares AgentX.
func New(opts Options) (*App, error) {
	if opts.AgentAddress == "" {
		opts.AgentAddress = "localhost:705"
	}
	if opts.PollPeriod <= 0 {
		opts.PollPeriod = 30 * time.Second
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: levelFor(opts.Debug),
	}))

	cfg, err := mib.LoadConfig(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if opts.ConfigPath != "" {
		logger.Info("loaded vppcfg", "path", opts.ConfigPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := vpp.NewClient(vpp.Options{Logger: logger, PollPeriod: opts.PollPeriod})
	if err := client.Connect(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("vpp connect: %w", err)
	}

	a := &App{
		opts: opts, log: logger, cfg: cfg,
		vpp: client, ctx: ctx, cancel: cancel,
	}
	a.agent = agentx.NewAgent(opts.AgentAddress, opts.PollPeriod, opts.AgentXDebug,
		a.setup, a.update)
	return a, nil
}

func levelFor(debug bool) slog.Level {
	if debug {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// Run blocks: it registers IF-MIB subtrees, primes the dataset, then serves AgentX
// GET/GETNEXT while re-polling VPP on the configured period.
func (a *App) Run() error {
	a.log.Info("starting", "agentx", a.opts.AgentAddress, "period", a.opts.PollPeriod)
	return a.agent.Run()
}

// Stop terminates the poll loop and releases VPP + AgentX resources.
func (a *App) Stop() {
	a.cancel()
	a.agent.Stop()
	a.vpp.Disconnect()
	a.wg.Wait()
}

// setup runs once from agentx.Agent before the serving loop starts.
func (a *App) setup() bool {
	a.agent.Register(ifTableOID, ifXTableOID)
	return true
}

// update is invoked periodically; it returns nil when VPP is unreachable so the
// agent keeps serving the last good dataset (Python behaviour).
func (a *App) update() *agentx.DataSet {
	snap, err := a.snapshot()
	if err != nil {
		a.log.Error("vpp poll failed", "err", err)
		return nil
	}
	return mib.Build(snap)
}

func (a *App) snapshot() (mib.Snapshot, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()

	ifaces, err := a.vpp.Interfaces(ctx)
	if err != nil {
		return mib.Snapshot{}, err
	}
	pairs, _ := a.vpp.LCPPairs(ctx)
	names, counters, err := a.vpp.InterfaceCounters(ctx)
	if err != nil {
		return mib.Snapshot{}, err
	}
	return mib.Snapshot{
		Names:    names,
		Counters: counters,
		Ifaces:   ifaces,
		LCPPairs: pairs,
		Config:   a.cfg,
	}, nil
}
