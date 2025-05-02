package network

import (
	"errors"
	"regexp"
	"time"

	"github.com/go-resty/resty/v2"
)

// ValidIP4 checks if a string is a valid IPv4 address
func ValidIP4(ip string) bool {
	ipv4Regex := `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	return regexp.MustCompile(ipv4Regex).MatchString(ip)
}

// PublicIP attempts to determine the public IPv4 address of the current machine
func PublicIP() (string, error) {
	client := resty.New().SetTimeout(5 * time.Second)
	hosts := []string{
		"https://ip4.ip8.com",
		"https://ip8.com/ip",
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://myexternalip.com/raw",
	}

	for _, host := range hosts {
		resp, err := client.R().Get(host)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 && ValidIP4(string(resp.Body())) {
			return string(resp.Body()), nil
		}
	}

	return "", errors.New("could not determine public IP address")
}

// IsIncoming determines if traffic is incoming based on the public IP
func IsIncoming(srcIP, dstIP string, publicIP string) bool {
	if publicIP == "" {
		return false
	}
	return dstIP == publicIP
}

// IsOutgoing determines if traffic is outgoing based on the public IP
func IsOutgoing(srcIP, dstIP string, publicIP string) bool {
	if publicIP == "" {
		return false
	}
	return srcIP == publicIP
}
