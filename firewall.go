package firewall

import (
	"log"
)

const (
	FIREWALL_IPTABLES = iota + 1
)

type Firewall struct {
	// Servers
	// [ServerName]*ServerObject
	Servers map[string]*Server `json:"servers,omitempty"`
	// Global Firewall Rules
	// list of types can be found in `firewall.go`
	// 1 can be used for iptables
	FirewallType int `json:"firewall-type,omitempty"`
	// Before Server.FirewallRulesBefore
	FirewallRulesBefore []*Firewall_Rule `json:"firewall-rules-before,omitempty"`
	// After Server.FirewallRulesAfter
	FirewallRulesAfter []*Firewall_Rule `json:"firewall-rules-after,omitempty"`
	// Global Variables
	Vars map[string]interface{} `json:"vars,omitempty"`
}

func (self *Firewall) IsValid() bool {
	if self == nil {
		log.Println("firewall nil")
		return false
	}
	if self.FirewallType != FIREWALL_IPTABLES {
		log.Printf("firewall.FirewallType: %d INVALID\n", self.FirewallType)
		return false
	}
	if len(self.Servers) == 0 {
		log.Println("firewall.Servers empty")
		return false
	}
	for name, server := range self.Servers {
		if name == "" {
			log.Println("firewall.Servers[] name empty")
			return false
		}
		if !server.IsValid() {
			log.Printf("firewall.Servers[%s] server invalid\n", name)
			return false
		}
	}
	// FirewallRulesBefore can be empty
	for _, rule := range self.FirewallRulesBefore {
		if !rule.IsValid() {
			log.Println("firewall.FirewallRulesBefore rule invalid")
			return false
		}
	}
	// FirewallRulesAfter can be empty
	for _, rule := range self.FirewallRulesAfter {
		if !rule.IsValid() {
			log.Println("firewall.FirewallRulesAfter rule invalid")
			return false
		}
	}
	return true
}

func (self *Firewall) isFirewallValid(
	name string,
	server *Server,
) bool {
	// this function is only for checking our relations of our dependencies
	// check external dependencies that rely on us
	// check if any servers have acquired services from this network
	for server_name2, server2 := range self.Servers {
		// compare the name not the server object
		// since we may reuse the same object under different names
		if name == server_name2 {
			// this is ourself!!!
			// make sure that we don't depend on ourselves
			for _, network := range server.Networks {
				if _, ok := network.ServiceDependencies[name]; ok {
					// we rely on ourselves!!!
					log.Printf("isFirewallValid(%s) this server requires dependencies from its self!!!\n", name)
					return false
				}
			}
			// we don't rely on ourself
		} else {
			// check their server networks
			for _, network2 := range server2.Networks {
				// check if they depend on our server
				// [ServerName][NetworkName][ServiceName]Service
				if networks2, ok := network2.ServiceDependencies[name]; ok {
					// network2 depends on us
					// compare all the networks that network2 depends on us for
					// if we don't find a network that they depend on us for we have to fail
					// [NetworkName][ServiceName]Service
					for network_name2, services2 := range networks2 {
						// check to make sure the network exists in our server
						if _, ok := server.Networks[network_name2]; !ok {
							// network doesn't exist
							log.Printf("isFirewallValid(%s) acquirable server: \"%s\" requested network: \"%s\" that doesn't exist\n", name, server_name2, network_name2)
							return false
						}
						// compare all services that they depend on us for
						// if we don't find a service they depend on us for we have to fail
						for service_name2, _ := range services2 {
							// check to make sure the service exists in our network
							if _, ok := server.Networks[network_name2].ServicesAcquirable[service_name2]; !ok {
								// network service doesn't exist
								log.Printf("buildFirewallIPTables(%s) acquirable server: \"%s\" requested network: \"%s\" service: \"%s\" that doesn't exist\n", name, server_name2, network_name2, service_name2)
								return false
							}
						}
					}
				}
			}
		}
	}
	// we have to check out dependencies
	// if we're building every server this will automatically be checked above overtime
	// if we're building an individual server we need to check them now, so this is always going to be checked
	for _, network := range server.Networks {
		// check that server exists
		// [ServerName][NetworkName][ServiceName]Service
		for server_name2, networks2 := range network.ServiceDependencies {
			if _, ok := self.Servers[server_name2]; !ok {
				log.Printf("buildFirewallIPTables(%s) dependent server: \"%s\" doesn't exist\n", name, server_name2)
				return false
			}
			// server found
			// check that network exists
			// [NetworkName][ServiceName]Service
			for network_name2, services2 := range networks2 {
				if _, ok := self.Servers[server_name2].Networks[network_name2]; !ok {
					log.Printf("buildFirewallIPTables(%s) dependent server: \"%s\" network: \"%s\" doesn't exist\n", name, server_name2, network_name2)
					return false
				}
				// network found
				// check that service exists
				// [ServiceName]Service
				for service_name2, _ := range services2 {
					if _, ok := self.Servers[server_name2].Networks[network_name2].ServicesAcquirable[service_name2]; !ok {
						log.Printf("buildFirewallIPTables(%s) dependent server: \"%s\" network: \"%s\" service: \"%s\" doesn't exist\n", name, server_name2, network_name2, service_name2)
						return false
					}
				}
			}
		}
	}
	return true
}
