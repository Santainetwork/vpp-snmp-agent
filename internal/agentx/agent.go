package agentx

import (
	"errors"
	"log"
	"sync"
	"time"
)

// ErrSetupFailed is returned by Agent.Run when the setup callback reports
// failure.
var ErrSetupFailed = errors.New("agentx: setup failed")

// Agent is the port of class Agent in agent.py. The setup and update callbacks
// are the Go equivalents of the Python overridable setup()/update() methods:
// setup returning false aborts Run; update returning nil keeps serving the last
// dataset.
type Agent struct {
	net         *Network
	oidList     []string
	setupFunc   func() bool
	updateFunc  func() *DataSet
	updateEvery time.Duration
	debug       bool

	mu         sync.Mutex
	lastUpdate time.Time
	stopCh     chan struct{}
	doneCh     chan struct{}
}

// NewAgent constructs an Agent for serverAddress. setup is called once before
// serving (returning false aborts Run); update is called every period to
// produce a fresh DataSet. Either callback may be nil.
func NewAgent(serverAddress string, period time.Duration, debug bool, setup func() bool, update func() *DataSet) *Agent {
	return &Agent{
		net:         NewNetwork(serverAddress, debug),
		setupFunc:   setup,
		updateFunc:  update,
		updateEvery: period,
		debug:       debug,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
}

// Register adds one or more subtree OIDs to the registration list, skipping
// duplicates (Agent.register).
func (a *Agent) Register(subtreeOID string, more ...string) {
	a.registerOne(subtreeOID)
	for _, oid := range more {
		a.registerOne(oid)
	}
}

func (a *Agent) registerOne(oid string) {
	for _, existing := range a.oidList {
		if existing == oid {
			return
		}
	}
	a.oidList = append(a.oidList, oid)
}

// update mirrors Agent._update: call the update callback, push the dataset into
// the network, and stamp the last successful update time.
func (a *Agent) update() bool {
	if a.updateFunc == nil {
		return false
	}
	ds := a.updateFunc()
	if ds == nil {
		return false
	}
	_, data := ds.Data()
	a.net.Update(data)
	a.mu.Lock()
	a.lastUpdate = time.Now()
	a.mu.Unlock()
	return true
}

// Run mirrors Agent.run: call the setup callback once, do an initial update,
// then loop reconnecting the AgentX session, refreshing the dataset every
// period, and answering requests until Stop is called. It blocks. It returns
// ErrSetupFailed if setup fails, otherwise nil when stopped or when the last
// error was a connection error (the loop keeps retrying those).
func (a *Agent) Run() error {
	defer close(a.doneCh)
	if a.setupFunc != nil && !a.setupFunc() {
		log.Println("[agentx] setup failed - exiting")
		return ErrSetupFailed
	}
	a.update()

	for {
		select {
		case <-a.stopCh:
			return nil
		default:
		}

		if !a.net.IsConnected() {
			log.Println("[agentx] opening AgentX connection")
			if err := a.net.Start(a.oidList); err != nil {
				log.Printf("[agentx] connect failed: %v", err)
				if !sleepOrStop(a.stopCh, time.Second) {
					return nil
				}
				continue
			}
		}

		a.mu.Lock()
		stale := time.Since(a.lastUpdate) > a.updateEvery
		a.mu.Unlock()
		if stale {
			if !a.update() {
				log.Println("[agentx] update failed, keeping previous dataset")
				if !sleepOrStop(a.stopCh, time.Second) {
					return nil
				}
			}
		}

		if err := a.net.Run(100 * time.Millisecond); err != nil {
			log.Printf("[agentx] disconnecting due to exception: %v", err)
			a.net.Disconnect()
			if !sleepOrStop(a.stopCh, time.Second) {
				return nil
			}
		}
	}
}

// sleepOrStop waits for d or the stop signal; false means stop was requested.
func sleepOrStop(stopCh <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stopCh:
		return false
	case <-t.C:
		return true
	}
}

// Stop interrupts Run and closes the AgentX connection (Agent.stop). It blocks
// until Run has returned.
func (a *Agent) Stop() {
	select {
	case <-a.stopCh:
	default:
		close(a.stopCh)
	}
	<-a.doneCh
	a.net.Disconnect()
}
