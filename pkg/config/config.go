package config

import (
	"net"

	"github.com/7c/sni-capture-go/pkg/logger"
)

// Config holds the configuration for packet capture
type Config struct {
	Direction string
	Ports     []int
	Interface *net.Interface
	Verbose   bool
	PublicIP  string
	LockPort  *int
}

// NewConfig creates a new configuration
func NewConfig(direction string, ports []int, iface *net.Interface, verbose bool, lockPort *int) *Config {
	// Use the public IP that was already determined in logger.InitLogger
	publicIP := logger.GetExternalIP()

	return &Config{
		Direction: direction,
		Ports:     ports,
		Interface: iface,
		Verbose:   verbose,
		PublicIP:  publicIP,
		LockPort:  lockPort,
	}
}

// IsIncoming returns true if the direction is "in" or "both"
func (c *Config) IsIncoming() bool {
	return c.Direction == "in" || c.Direction == "both"
}

// IsOutgoing returns true if the direction is "out" or "both"
func (c *Config) IsOutgoing() bool {
	return c.Direction == "out" || c.Direction == "both"
}
