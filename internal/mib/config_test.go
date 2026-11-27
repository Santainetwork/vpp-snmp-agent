package mib

import "testing"

func TestConfigDescription(t *testing.T) {
	c := Config{Interfaces: map[string]struct {
		Description string `yaml:"description"`
		LCP         string `yaml:"lcp"`
		Sub         map[uint32]struct {
			Description string `yaml:"description"`
		} `yaml:"sub-interfaces"`
	}{"GigabitEthernet3/0/0": {Description: "uplink", Sub: map[uint32]struct {
		Description string `yaml:"description"`
	}{20011: {Description: "customer"}}}}}
	if got := c.Description("GigabitEthernet3/0/0.20011"); got != "customer" {
		t.Fatalf("Description() = %q", got)
	}
}
