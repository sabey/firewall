package firewall

import (
	"log"
	"net"
)

type Network struct {
	// Accessible IP
	IP string `json:"ip,omitempty"`
	// []Host
	// Hosts are referenced by other Servers
	// if referenced, hosts are appended to their /etc/hosts
	Hosts []string `json:"hosts,omitempty"`
	// Passive Services
	// passive services will always be available in the firewall rules
	// [ServiceName]Service
	ServicesPassive map[string]*Service `json:"services-passive,omitempty"`
	// Acquirable Services
	// acquirable services will only be available in firewall rules if acquired
	// [ServiceName]Service
	ServicesAcquirable map[string]*Service `json:"services-acquirable,omitempty"`
	// Optional Service Dependencies
	// Acquired Services will set firewall rules in the acquirable Servers firewall rules
	// this Service object here is optional and will be included in this Servers rules
	// [ServerName][NetworkName][ServiceName]Service
	ServiceDependencies map[string]map[string]map[string]*Service `json:"service-dependencies,omitempty"`
	// Before Server.FirewallRulesBefore
	FirewallRulesBefore []*Firewall_Rule `json:"firewall-rules-before,omitempty"`
	// After Server.FirewallRulesAfter
	FirewallRulesAfter []*Firewall_Rule `json:"firewall-rules-after,omitempty"`
	// Network Variables
	Vars map[string]interface{} `json:"vars,omitempty"`
}

func (self *Network) IsValid() bool {
	if self == nil {
		log.Println("Network nil")
		return false
	}
	if self.IP == "" {
		log.Println("Network.IP empty")
		return false
	}
	if net.ParseIP(self.IP) == nil {
		log.Println("Network.IP invalid")
		return false
	}
	// Hosts can be empty
	for _, host := range self.Hosts {
		// individual Hosts can not be empty
		if host == "" {
			log.Println("Network.Hosts host empty")
			return false
		}
	}
	// ServicesPassive can be empty
	for servicename, service := range self.ServicesPassive {
		if !service.IsValid() {
			log.Printf("Network.ServicesPassive[%s] service invalid\n", servicename)
			return false
		}
	}
	// ServicesAcquirable can be empty
	for servicename, service := range self.ServicesAcquirable {
		if !service.IsValid() {
			log.Printf("Network.ServicesAcquirable[%s] service invalid\n", servicename)
			return false
		}
	}
	// ServiceDependencies can be empty
	// Service objects are optional, and their values are optional
	// if port is set then it will be used as the source port
	// if rule is not empty then it will be used locally as a rule
	// there's no current reason to validate them, if we need to in the future keep that in mind
	/*for servername, networks := range self.ServiceDependencies {
		for networkname, services := range networks {
			for servicename, service := range services {
				// Service can be nil
				// Service should only be set if we need local firewall settings
				if service != nil && !service.IsValid() {
					log.Printf("Dependency.Services[%s][%s][%s] service invalid\n", servername, networkname, servicename)
					return false
				}
			}
		}
	}*/
	return true
}
