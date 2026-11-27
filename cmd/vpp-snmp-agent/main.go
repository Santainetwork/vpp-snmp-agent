// Command vpp-snmp-agent is the Go replacement for the legacy Python VPP SNMP AgentX daemon.
//
// It exposes the IF-MIB by periodically polling VPP and publishing results over
// the Net-SNMP AgentX protocol. Runtime behaviour lives in internal/app; this
// command only parses flags, wires up logging, and forwards OS signals.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	vppsnmpagent "github.com/santainetwork/vpp-snmp-agent/internal/app"
)

const (
	defaultAddress = "localhost:705"
	defaultPeriod  = 30 * time.Second
)

func main() {
	var (
		address     = flag.String("a", defaultAddress, "Location of the SNMPd agent (unix-path or host:port)")
		period      = flag.String("p", defaultPeriod.String(), "Period to poll VPP (Go duration, e.g. 30s)")
		configPath  = flag.String("c", "", "Optional vppcfg YAML configuration file")
		debug       = flag.Bool("d", false, "Enable debug logging")
		agentxDebug = flag.Bool("dd", false, "Enable debug logging for AgentX PDUs")
	)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), `
Examples:
  %s -a localhost:705 -p 30s
  %s -a /var/agentx-dataplane/master -p 15s -c /etc/vpp/vpp-snmp-agent.yaml -d
`, os.Args[0], os.Args[0])
	}

	flag.Parse()

	pollPeriod, err := time.ParseDuration(*period)
	if err != nil {
		log.Fatalf("invalid -p value %q: must be a duration like 30s, 1m: %v", *period, err)
	}
	if pollPeriod <= 0 {
		log.Fatalf("invalid -p value %q: must be positive", *period)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if *debug || *agentxDebug {
		log.SetOutput(os.Stderr)
	}

	app, err := vppsnmpagent.New(vppsnmpagent.Options{
		AgentAddress: *address,
		PollPeriod:   pollPeriod,
		ConfigPath:   *configPath,
		Debug:        *debug,
		AgentXDebug:  *agentxDebug,
	})
	if err != nil {
		log.Fatalf("vpp-snmp-agent: initialization failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runErr := make(chan error, 1)
	go func() {
		runErr <- app.Run()
	}()

	select {
	case err := <-runErr:
		if err != nil {
			log.Fatalf("vpp-snmp-agent: run failed: %v", err)
		}
	case <-ctx.Done():
		log.Print("vpp-snmp-agent: shutdown signal received")
		app.Stop()
		if err := <-runErr; err != nil {
			log.Fatalf("vpp-snmp-agent: run returned error during shutdown: %v", err)
		}
	}

	log.Print("vpp-snmp-agent: exited cleanly")
}
