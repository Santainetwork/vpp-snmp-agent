# VPP SNMP Agent (Go)

Go replacement for the [Python `vpp-snmp-agent`](https://github.com/pimvanpelt/vpp-snmp-agent).
It exposes the IF-MIB to Net-SNMP over the [AgentX](https://datatracker.ietf.org/doc/html/rfc2257)
protocol by periodically polling VPP, rewriting `ifName`/`ifAlias` the same way the Python
agent does. The Python implementation is left in `/root/vpp-snmp-agent` (not deleted); this
repo builds a single static binary with no runtime Python dependency.

## Requirements

- **VPP** running with the `linux-cp` plugin enabled.
- Read access to `/run/vpp/stats.sock` and read/write access to `/run/vpp/api.sock`. Typically
  done by running the agent as group `vpp` (see `vpp-snmp-agent.service`).
- **Net-SNMP** (`apt install snmpd`) configured as AgentX master. Add to `snmpd.conf`:
  ```
  master  agentx
  agentXSocket tcp:localhost:705,unix:/var/agentx-dataplane/master
  ```
  A TCP AgentX socket is preferred so the agent can run unprivileged. The unix socket
  `/var/agentx/master` is root-only.
- **govpp compatibility**: the Go bindings in `go.mod` are generated against a specific VPP
  release (see `go.fd.io/govpp` version). The binary is only expected to work against the
  matching production VPP; backward compatibility with older VPP API releases is not a goal.
  Regenerate bindings when upgrading VPP.

## Installation

Latest release (requires Go 1.26+):

```
go install github.com/santainetwork/vpp-snmp-agent/cmd/vpp-snmp-agent@latest
```

From a checkout:

```
make build              # ./vpp-snmp-agent
make install            # go install into $GOPATH/bin
make test
```

Reproducible build:

```
go build -trimpath -ldflags="-s -w" -o vpp-snmp-agent ./cmd/vpp-snmp-agent
sudo cp vpp-snmp-agent /usr/sbin/
```

## Usage

```
vpp-snmp-agent [options]

  -a string   SNMPd agent address, host:port or unix path (default "localhost:705")
  -p string   Poll period, Go duration (default "30s")
  -c string   Optional vppcfg YAML configuration file
  -d          Enable debug logging
  -dd         Enable debug logging for AgentX PDUs
```

Examples:

```
vpp-snmp-agent -a localhost:705 -p 30s
vpp-snmp-agent -a /var/agentx-dataplane/master -p 15s -c /etc/vpp/vpp-snmp-agent.yaml -d
```

## Configuration (optional)

The `-c` flag points at a [vppcfg](https://github.com/pimvanpelt/vppcfg) YAML file. Only the
`interfaces:` block is read; everything else is ignored. See `vpp-snmp-agent.yaml` for an example.

Without a config file, the agent enumerates all VPP interfaces and sets `ifAlias` equal to
`ifName`. With a config file:

- `ifAlias` is set to the interface `description`.
- `tapNN` interfaces are matched to their PHY via the `lcp` (Linux Control Plane) field:
  `ifName` is rewritten to the LCP host-if (e.g. `tap3` becomes `e0`), and `ifAlias` becomes
  `LCP <phy-ifName>` (e.g. `LCP GigabitEthernet3/0/0.20011 (tap3)`).

## Running in production

Meant for Ubuntu/Debian. Install snmpd, copy the unit files, then disable the default snmpd
and bring up the dataplane namespace stack:

```
sudo cp vpp-snmp-agent.service /usr/lib/systemd/system/
sudo cp snmpd-dataplane.service /usr/lib/systemd/system/
sudo cp netns-dataplane.service /usr/lib/systemd/system/
sudo cp vpp-snmp-agent.yaml /etc/vpp/vpp-snmp-agent.yaml
sudo systemctl daemon-reload
sudo systemctl stop snmpd && sudo systemctl disable snmpd
sudo systemctl enable --now netns-dataplane
sudo systemctl enable --now snmpd-dataplane
sudo systemctl enable --now vpp-snmp-agent
```

## Support

Compatible only with the current production VPP release on
[Gerrit](https://gerrit.fd.io/r/q/repo:vpp); backward compatibility is not a goal. Bug
reports against the code are welcome; end-user support is not provided. See `LICENSE`.
