package firewall

import (
	"sort"
)

type firewall struct {
	ServerName        string
	Server            *Server
	IPs               []string
	GlobalRulesBefore []*firewall_rule_server
	ServerRulesBefore []*firewall_rule_server
	Networks          map[string]*firewall_network
	ServerRulesAfter  []*firewall_rule_server
	GlobalRulesAfter  []*firewall_rule_server
}
type firewall_rule_server struct {
	Rule      *Firewall_Rule
	Variables *Firewall_Variables_Server
}
type firewall_rule_network struct {
	Rule      *Firewall_Rule
	Variables *Firewall_Variables_Network
}
type firewall_rule_service_passive struct {
	Rule      *Firewall_Rule
	Variables *Firewall_Variables_Service_Passive
}
type firewall_rule_service_acquirable struct {
	Rule      *Firewall_Rule
	Variables *Firewall_Variables_Service_Acquirable
}
type firewall_rule_service_dependencies struct {
	Rule      *Firewall_Rule
	Variables *Firewall_Variables_Service_Dependencies
}
type firewall_network struct {
	Network             *Network
	ServicesPassive     map[string][]*firewall_rule_service_passive
	ServicesAcquirable  map[string]map[string][]*firewall_rule_service_acquirable
	ServiceDependencies map[string]map[string][]*firewall_rule_service_dependencies
	RulesBefore         []*firewall_rule_network
	RulesAfter          []*firewall_rule_network
}

func (self *Firewall) buildFirewall(
	name string,
	server *Server,
) *firewall {
	// we're building an object to return for templating
	// this will allow us to reuse the same parsed object for different firewalls
	f := &firewall{
		ServerName: name,
		Server:     server,
		Networks:   make(map[string]*firewall_network),
	}
	// append only unique IPs
	unique := make(map[string]struct{})
	for _, network := range server.Networks {
		unique[network.IP] = struct{}{}
	}
	// this is an extremely basic sort method for ips
	// I only care that the output is deterministic
	for ip, _ := range unique {
		f.IPs = append(f.IPs, ip)
	}
	// sort IPs
	sort.Strings(f.IPs)
	// append global variables
	server_vars := &Firewall_Variables_Server{
		ServerName: name,
		Server:     server,
		Firewall:   self,
	}
	// global rules before
	for _, rule := range self.FirewallRulesBefore {
		// append rule
		f.GlobalRulesBefore = append(
			f.GlobalRulesBefore,
			&firewall_rule_server{
				Rule:      rule,
				Variables: server_vars,
			},
		)
	}
	// server rules before
	for _, rule := range server.FirewallRulesBefore {
		// append rule
		f.ServerRulesBefore = append(
			f.ServerRulesBefore,
			&firewall_rule_server{
				Rule:      rule,
				Variables: server_vars,
			},
		)
	}
	// passive services
	// we don't need to sort services here!!!
	for network_name, network := range server.Networks {
		// network doesn't exist yet, so we have to create an object for it
		f.Networks[network_name] = &firewall_network{
			Network:             network,
			ServicesPassive:     make(map[string][]*firewall_rule_service_passive),
			ServicesAcquirable:  make(map[string]map[string][]*firewall_rule_service_acquirable),
			ServiceDependencies: make(map[string]map[string][]*firewall_rule_service_dependencies),
		}
		network_vars := &Firewall_Variables_Network{
			ServerName:  name,
			Server:      server,
			NetworkName: network_name,
			Network:     network,
			Firewall:    self,
		}
		// network rules before
		for _, rule := range network.FirewallRulesBefore {
			// append rule
			f.Networks[network_name].RulesBefore = append(
				f.Networks[network_name].RulesBefore,
				&firewall_rule_network{
					Rule:      rule,
					Variables: network_vars,
				},
			)
		}
		// network rules after
		for _, rule := range network.FirewallRulesAfter {
			// append rule
			f.Networks[network_name].RulesAfter = append(
				f.Networks[network_name].RulesAfter,
				&firewall_rule_network{
					Rule:      rule,
					Variables: network_vars,
				},
			)
		}
		// load passive services
		for service_name, service := range network.ServicesPassive {
			// set passive service
			for _, rule := range service.FirewallRules {
				// append passive rule
				f.Networks[network_name].ServicesPassive[service_name] = append(
					f.Networks[network_name].ServicesPassive[service_name],
					&firewall_rule_service_passive{
						Rule: rule,
						Variables: &Firewall_Variables_Service_Passive{
							ServerName:  name,
							Server:      server,
							NetworkName: network_name,
							Network:     network,
							ServiceName: service_name,
							Service:     service,
							Firewall:    self,
						},
					},
				)
			}
		}
	}
	// services acquired by others
	// we don't need to sort services here!!!
	// check external dependencies that rely on us
	// loop all of our available networks
	for network_name, network := range server.Networks {
		// loop all of the available servers
		// check if any servers have acquired services from this network
		for server_name2, server2 := range self.Servers {
			// loop all of that servers available networks
			for network_name2, network2 := range server2.Networks {
				// check if their network depends on our server
				// [ServerName][NetworkName][ServiceName]Service
				if networks2, ok := network2.ServiceDependencies[name]; ok {
					// check if they depend on our servers network
					// [NetworkName][ServiceName]Service
					if services2, ok := networks2[network_name]; ok {
						// check if they depend on our networks services
						// [ServiceName]Service
						for service_name2, service2 := range services2 {
							// check if they depend an individual service
							if service, ok := network.ServicesAcquirable[service_name2]; ok {
								// they depend on this service
								// make sure a network object has been created
								if _, ok := f.Networks[network_name]; !ok {
									// create network
									f.Networks[network_name] = &firewall_network{
										Network:             network,
										ServicesPassive:     make(map[string][]*firewall_rule_service_passive),
										ServicesAcquirable:  make(map[string]map[string][]*firewall_rule_service_acquirable),
										ServiceDependencies: make(map[string]map[string][]*firewall_rule_service_dependencies),
									}
									network_vars := &Firewall_Variables_Network{
										ServerName:  name,
										Server:      server,
										NetworkName: network_name,
										Network:     network,
										Firewall:    self,
									}
									// network rules before
									for _, rule := range network.FirewallRulesBefore {
										// append rule
										f.Networks[network_name].RulesBefore = append(
											f.Networks[network_name].RulesBefore,
											&firewall_rule_network{
												Rule:      rule,
												Variables: network_vars,
											},
										)
									}
									// network rules after
									for _, rule := range network.FirewallRulesAfter {
										// append rule
										f.Networks[network_name].RulesAfter = append(
											f.Networks[network_name].RulesAfter,
											&firewall_rule_network{
												Rule:      rule,
												Variables: network_vars,
											},
										)
									}
									// load acquired services
								}
								// set acquired service
								for _, rule := range service.FirewallRules {
									// append dependent rule
									if _, ok := f.Networks[network_name].ServicesAcquirable[service_name2]; !ok {
										// service server doesnt exist yet
										f.Networks[network_name].ServicesAcquirable[service_name2] = make(map[string][]*firewall_rule_service_acquirable)
									}
									f.Networks[network_name].ServicesAcquirable[service_name2][server_name2] = append(
										f.Networks[network_name].ServicesAcquirable[service_name2][server_name2],
										&firewall_rule_service_acquirable{
											Rule: rule,
											// source is always the imported dependency
											// destination is the importer
											Variables: &Firewall_Variables_Service_Acquirable{
												// source service_name and destination service_name will always be the same
												ServiceName:       service_name2,
												SourceServerName:  server_name2,
												SourceServer:      server2,
												SourceNetworkName: network_name2,
												SourceNetwork:     network2,
												// source service and destination service can be different
												// source service is an optional object
												SourceService:          service2,
												DestinationServerName:  name,
												DestinationServer:      server,
												DestinationNetworkName: network_name,
												DestinationNetwork:     network,
												DestinationService:     service,
												Firewall:               self,
											},
										},
									)
								}
							}
						}
					}
				}
			}
		}
	}
	// dependent services
	// dependent services are rules that are triggered when we import a dependency
	// we don't need to sort services here!!!
	// include any rules that will be triggered on including a dependency
	for network_name, network := range server.Networks {
		// loop dependencies
		// [ServerName][NetworkName][ServiceName]Service
		for server_name2, networks2 := range network.ServiceDependencies {
			// [NetworkName][ServiceName]Service
			for network_name2, services2 := range networks2 {
				// [ServiceName]Service
				for service_name2, service := range services2 {
					// service is our local service object, not the remote service, thus it is service not service2
					// service is optional, rules are only triggered if service is non nil
					if service != nil {
						for _, rule := range service.FirewallRules {
							// make sure a network object has been created
							if _, ok := f.Networks[network_name]; !ok {
								// create network
								f.Networks[network_name] = &firewall_network{
									Network:             network,
									ServicesPassive:     make(map[string][]*firewall_rule_service_passive),
									ServicesAcquirable:  make(map[string]map[string][]*firewall_rule_service_acquirable),
									ServiceDependencies: make(map[string]map[string][]*firewall_rule_service_dependencies),
								}
								network_vars := &Firewall_Variables_Network{
									ServerName:  name,
									Server:      server,
									NetworkName: network_name,
									Network:     network,
									Firewall:    self,
								}
								// network rules before
								for _, rule := range network.FirewallRulesBefore {
									// append rule
									f.Networks[network_name].RulesBefore = append(
										f.Networks[network_name].RulesBefore,
										&firewall_rule_network{
											Rule:      rule,
											Variables: network_vars,
										},
									)
								}
								// network rules after
								for _, rule := range network.FirewallRulesAfter {
									// append rule
									f.Networks[network_name].RulesAfter = append(
										f.Networks[network_name].RulesAfter,
										&firewall_rule_network{
											Rule:      rule,
											Variables: network_vars,
										},
									)
								}
								// load dependent services
							}
							if _, ok := f.Networks[network_name].ServiceDependencies[service_name2]; !ok {
								// service server doesnt exist yet
								f.Networks[network_name].ServiceDependencies[service_name2] = make(map[string][]*firewall_rule_service_dependencies)
							}
							f.Networks[network_name].ServiceDependencies[service_name2][server_name2] = append(
								f.Networks[network_name].ServiceDependencies[service_name2][server_name2],
								&firewall_rule_service_dependencies{
									Rule: rule,
									// source is always the imported dependency
									// destination is the importer
									Variables: &Firewall_Variables_Service_Dependencies{
										// source service_name and destination service_name will always be the same
										ServiceName:       service_name2,
										SourceServerName:  server_name2,
										SourceServer:      self.Servers[server_name2],
										SourceNetworkName: network_name2,
										SourceNetwork:     self.Servers[server_name2].Networks[network_name2],
										// source service and destination service are different
										// source service is not optional because it was triggered on importing the dependency
										// since source service_name and destination service_name will always be the same
										// we can use service_name to find our source service
										SourceService:          self.Servers[server_name2].Networks[network_name2].ServicesAcquirable[service_name2],
										DestinationServerName:  name,
										DestinationServer:      server,
										DestinationNetworkName: network_name,
										DestinationNetwork:     network,
										DestinationService:     service,
										Firewall:               self,
									},
								},
							)
						}
					}
				}
			}
		}
	}
	// server rules after
	for _, rule := range server.FirewallRulesAfter {
		// append rule
		f.ServerRulesAfter = append(
			f.ServerRulesAfter,
			&firewall_rule_server{
				Rule:      rule,
				Variables: server_vars,
			},
		)
	}
	// global rules after
	for _, rule := range self.FirewallRulesAfter {
		// append rule
		f.GlobalRulesAfter = append(
			f.GlobalRulesAfter,
			&firewall_rule_server{
				Rule:      rule,
				Variables: server_vars,
			},
		)
	}
	return f
}
