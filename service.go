package firewall

import (
	"log"
)

type Service struct {
	Port          uint16           `json:"port,omitempty"`
	FirewallRules []*Firewall_Rule `json:"rules,omitempty"`
	// Service Variables
	Vars map[string]interface{} `json:"vars,omitempty"`
}

func (self *Service) IsValid() bool {
	if self == nil {
		log.Println("Service nil")
		return false
	}
	// FirewallRules can't be empty
	if len(self.FirewallRules) == 0 {
		log.Println("Service.FirewallRules empty")
		return false
	}
	for _, rule := range self.FirewallRules {
		if !rule.IsValid() {
			log.Println("Service.FirewallRules rule invalid")
			return false
		}
	}
	return true
}
