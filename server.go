package firewall

import (
	"log"
	"net"
)

type Server struct {
	// Hostname is used for our /etc/hostname and /etc/hosts
	Hostname string `json:"hostname,omitempty"`
	// Additional Local Hosts are appended to our /etc/hosts
	// this appears locally only
	// [IP][]Host
	Hosts map[string][]string `json:"hosts,omitempty"`
	// Hosts Custom Blob of Text Before
	// this appears locally only
	HostsBefore string `json:"hosts-before,omitempty"`
	// Hosts Custom Blob of Text After
	// this appears locally only
	HostsAfter string `json:"hosts-after,omitempty"`
	// Optional Hosts Dependencies
	// Additional referenced Hosts are appended to our /etc/hosts
	// if we reference another Servers Network, we will include that Networks /etc/hosts locally and point the hosts to that Networks IP
	// [ServerName][]Network
	HostsDependencies map[string][]string `json:"hosts-dependencies,omitempty"`
	// SSH
	// this will generate a list of ssh commands for possible local or remote tunnels
	// this appears locally only
	// ssh service name are arbitrary and aren't currently referenced
	// [Service]SSH
	SSH map[string]*SSH `json:"ssh,omitempty"`
	// Firewall Rules
	// Before Services
	FirewallRulesBefore []*Firewall_Rule `json:"firewall-before,omitempty"`
	// After Services
	FirewallRulesAfter []*Firewall_Rule `json:"firewall-after,omitempty"`
	// List of our Accessible Networks and their available Services
	// our Firewall rules will be built from our Network relations
	// NetworkName can be used in place of the Interface name
	// the Interface name can be referenced for specific firewall rules
	// [NetworkName]Network
	Networks map[string]*Network `json:"networks,omitempty"`
	// Server Variables
	Vars map[string]interface{} `json:"vars,omitempty"`
}

func (self *Server) IsValid() bool {
	if self == nil {
		log.Println("Server nil")
		return false
	}
	if self.Hostname == "" {
		log.Println("Server.Hostname empty")
		return false
	}
	// Hosts can be empty
	for ip, hosts := range self.Hosts {
		// key must be non empty
		if ip == "" {
			log.Printf("Server.Hosts[]{%s} IP empty\n", hosts)
			return false
		}
		if net.ParseIP(ip) == nil {
			log.Printf("Server.Hosts[%s]{%s} IP invalid\n", ip, hosts)
			return false
		}
		if len(hosts) == 0 {
			log.Printf("Server.Hosts[%s]{%s} Hosts Empty\n", ip, hosts)
			return false
		}
		for _, host := range hosts {
			// individual Hosts can not be empty
			if host == "" {
				log.Printf("Server.Hosts[%s]{%s} host empty\n", ip, hosts)
				return false
			}
		}
	}
	// HostsDependencies can be empty
	for name, networks := range self.HostsDependencies {
		if name == "" {
			log.Println("Dependency.HostsDependencies[] name empty")
			return false
		}
		if len(networks) == 0 {
			log.Printf("Dependency.HostsDependencies[%s]{%s} networks empty\n", name, networks)
			return false
		}
		for _, network := range networks {
			if network == "" {
				log.Printf("Dependency.HostsDependencies[%s] network empty\n", name)
				return false
			}
		}
	}
	// ssh is optional
	for _, ssh := range self.SSH {
		if !ssh.IsValid() {
			log.Println("Server.SSH ssh invalid")
			return false
		}
	}
	// FirewallRulesBefore can be empty
	for _, rule := range self.FirewallRulesBefore {
		if !rule.IsValid() {
			log.Println("Server.FirewallRulesBefore rule invalid")
			return false
		}
	}
	// FirewallRulesAfter can be empty
	for _, rule := range self.FirewallRulesAfter {
		if !rule.IsValid() {
			log.Println("Server.FirewallRulesAfter rule invalid")
			return false
		}
	}
	if len(self.Networks) == 0 {
		log.Println("Server.Networks empty")
		return false
	}
	for name, network := range self.Networks {
		if name == "" {
			log.Println("Server.Network[] name empty")
			return false
		}
		if !network.IsValid() {
			log.Printf("Server.Network[%s] network invalid\n", name)
			return false
		}
	}
	return true
}
