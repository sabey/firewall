package firewall

import (
	"log"
)

type SSH struct {
	User  string   `json:"user,omitempty"`
	Host  string   `json:"host,omitempty"`
	Port  uint16   `json:"port,omitempty"`
	Key   string   `json:"key,omitempty"`
	Flags []string `json:"flags,omitempty"`
	// Tunnel Settings
	Tunnel        bool `json:"tunnel,omitempty"`
	TunnelReverse bool `json:"tunnel-reverse,omitempty"`
	// For a regular Tunnel use:
	// ssh -L LocalPort:RemoteHost:RemotePort
	// For a Reverse Tunnel use:
	// ssh -R RemotePort:LocalHost:LocalPort
	LocalHost  string `json:"local-host,omitempty"`
	LocalPort  uint16 `json:"local-port,omitempty"`
	RemoteHost string `json:"remote-host,omitempty"`
	RemotePort uint16 `json:"remote-port,omitempty"`
}

func (self *SSH) IsValid() bool {
	if self == nil {
		log.Println("SSH nil")
		return false
	}
	// User is optional
	if self.Host == "" {
		log.Println("SSH.Host empty")
		return false
	}
	// Port is optional
	// Flag is optional
	for _, flag := range self.Flags {
		// flag must not be empty if it exists
		if flag == "" {
			log.Println("SSH.Flag empty")
			return false
		}
	}
	if self.Tunnel {
		// Tunnel
		if self.RemotePort < 1 {
			log.Println("SSH.RemotePort < 1")
			return false
		}
		if self.LocalPort < 1 {
			log.Println("SSH.LocalPort < 1")
			return false
		}
		if !self.TunnelReverse {
			// Regular Tunnel
			if self.RemoteHost == "" {
				log.Println("SSH.Tunnel.RemoteHost is empty")
				return false
			}
			// LocalHost is optional
		} else {
			// Reverse Tunnel
			if self.LocalHost == "" {
				log.Println("SSH.TunnelReverse.LocalHost is empty")
				return false
			}
			// RemoteHost is optional
		}
	}
	return true
}
