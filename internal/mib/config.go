package mib

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interfaces map[string]struct {
		Description string `yaml:"description"`
		LCP         string `yaml:"lcp"`
		Sub         map[uint32]struct {
			Description string `yaml:"description"`
		} `yaml:"sub-interfaces"`
	} `yaml:"interfaces"`
	Loopbacks    map[string]description `yaml:"loopbacks"`
	Taps         map[string]description `yaml:"taps"`
	VXLANTunnels map[string]description `yaml:"vxlan_tunnels"`
}

type description struct {
	Description string `yaml:"description"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, nil
}

func (c Config) Description(name string) string {
	if v, ok := c.Interfaces[name]; ok {
		return v.Description
	}
	for parent, v := range c.Interfaces {
		if !strings.HasPrefix(name, parent+".") {
			continue
		}
		var id uint32
		if _, err := fmt.Sscanf(strings.TrimPrefix(name, parent+"."), "%d", &id); err == nil {
			if sub, ok := v.Sub[id]; ok {
				return sub.Description
			}
		}
	}
	if v, ok := c.Loopbacks[name]; ok {
		return v.Description
	}
	if v, ok := c.Taps[name]; ok {
		return v.Description
	}
	if v, ok := c.VXLANTunnels[name]; ok {
		return v.Description
	}
	return ""
}

// Ponytail: consume interface descriptions and LCP mapping only; add other vppcfg fields when MIB needs them.
