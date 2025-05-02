package network

import (
	"fmt"
	"net"

	"github.com/fatih/color"
)

// GetInterface returns the network interface to use for packet capture
func GetInterface(ifaceName string) (*net.Interface, error) {
	if ifaceName != "" {
		return net.InterfaceByName(ifaceName)
	}
	return DefaultInterface()
}

// DefaultInterface returns the default network interface
func DefaultInterface() (*net.Interface, error) {
	_, defaultRoute, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return nil, err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting network interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Name == "lo" {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if defaultRoute.Contains(ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("default route interface not found")
}

// ListInterfaces displays all available network interfaces
func ListInterfaces() {
	defaultInterface, err := DefaultInterface()
	if err != nil {
		fmt.Printf("Error getting default interface: %v\n", err)
		return
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("Error getting interfaces: %v\n", err)
		return
	}

	for _, iface := range interfaces {
		if iface.Name == defaultInterface.Name {
			color.Blue("Name: %s (default)", iface.Name)
		} else {
			fmt.Println("Name:", iface.Name)
		}

		fmt.Println("Hardware Address (MAC):", iface.HardwareAddr)

		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("Error getting addresses:", err)
			continue
		}

		for _, addr := range addrs {
			fmt.Println("IP Address:", addr)
		}
		fmt.Println()
	}
}
