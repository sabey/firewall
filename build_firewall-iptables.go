package firewall

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
)

func (self *Firewall) buildFirewallIPTables(
	settings *Settings,
	name string,
	server *Server,
	fw *firewall,
) bool {
	file := fmt.Sprintf("%s/%s.iptables", self.pathFirewall(settings), name)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("buildFirewallIPTables(%s) failed to open iptables file: \"%s\"\n", name, err)
		return false
	}
	defer f.Close()
	buff := &bytes.Buffer{}
	// our header
	buff.WriteString("*filter\n\n")
	buff.WriteString(fmt.Sprintf("### Server: \"%s\"\n", name))
	buff.WriteString(fmt.Sprintf("### Hostname: \"%s\"\n", fw.Server.Hostname))
	buff.WriteString("### IPs: [")
	for i, ip := range fw.IPs {
		if i > 0 {
			buff.WriteString(", ")
		}
		buff.WriteString(ip)
	}
	buff.WriteString("]\n\n")
	// global rules before
	if len(fw.GlobalRulesBefore) > 0 {
		buff.WriteString("#######################\n")
		buff.WriteString("# Global Rules Before #\n")
		buff.WriteString("#######################\n")
		for _, rule := range fw.GlobalRulesBefore {
			// parse rule
			if err := rule.Rule.ParseServer(buff, rule.Variables); err != nil {
				log.Printf("buildFirewallIPTables(%s) failed to write global before rule: \"%s\"\n", name, err)
				return false
			}
			buff.WriteString("\n")
		}
		buff.WriteString("\n")
	}
	// server rules before
	if len(fw.ServerRulesBefore) > 0 {
		buff.WriteString("#######################\n")
		buff.WriteString("# Server Rules Before #\n")
		buff.WriteString("#######################\n")
		for _, rule := range fw.ServerRulesBefore {
			// parse rule
			if err := rule.Rule.ParseServer(buff, rule.Variables); err != nil {
				log.Printf("buildFirewallIPTables(%s) failed to write server before rule: \"%s\"\n", name, err)
				return false
			}
			buff.WriteString("\n")
		}
		buff.WriteString("\n")
	}
	if len(fw.Networks) > 0 {
		// sort networks so they're deterministic
		sorted := []string{}
		for network_name, _ := range fw.Networks {
			sorted = append(sorted, network_name)
		}
		sort.Strings(sorted)
		nf := false // don't print networks if it's not needed
		x := 0
		for _, network_name := range sorted {
			nsf := false // does this network have any services?
			network := fw.Networks[network_name]
			// passive services
			if len(network.ServicesPassive) > 0 {
				nsf = true
			}
			// services acquired by others
			if len(network.ServicesAcquirable) > 0 {
				nsf = true
			}
			// dependent services
			if len(network.ServiceDependencies) > 0 {
				nsf = true
			}
			// server firewall rules before
			if len(network.RulesBefore) > 0 {
				nsf = true
			}
			// server firewall rules after
			if len(network.RulesAfter) > 0 {
				nsf = true
			}
			if nsf && !nf {
				// network actually exists
				buff.WriteString("############\n")
				buff.WriteString("# Networks #\n")
				buff.WriteString("############\n")
				nf = true
			}
			if nsf {
				if x > 0 {
					// extra network
					buff.WriteString("\n")
				}
				x++
				// network services actually exist
				buff.WriteString(fmt.Sprintf("### Network: %s\n", network_name))
				buff.WriteString(fmt.Sprintf("### IP: %s\n", network.Network.IP))
				// server firewall rules before
				if len(network.RulesBefore) > 0 {
					buff.WriteString("########################\n")
					buff.WriteString("# Network Rules Before #\n")
					buff.WriteString("########################\n")
					for _, rule := range network.RulesBefore {
						// parse rule
						if err := rule.Rule.ParseNetwork(buff, rule.Variables); err != nil {
							log.Printf("buildFirewallIPTables(%s) failed to write network before \"%s\" rule: \"%s\"\n", name, network_name, err)
							return false
						}
						buff.WriteString("\n")
					}
				}
				// passive services
				if len(network.ServicesPassive) > 0 {
					buff.WriteString("######################\n")
					buff.WriteString("## Passive Services ##\n")
					buff.WriteString("######################\n")
					// sort passive services so they're deterministic
					sorted2 := []string{}
					for service_name, _ := range network.ServicesPassive {
						sorted2 = append(sorted2, service_name)
					}
					sort.Strings(sorted2)
					for _, service_name := range sorted2 {
						buff.WriteString(fmt.Sprintf("### Service: %s\n", service_name))
						for _, rule := range network.ServicesPassive[service_name] {
							// parse rule
							if err := rule.Rule.ParseServicePassive(buff, rule.Variables); err != nil {
								log.Printf("buildFirewallIPTables(%s) failed to write passive service \"%s\" rule: \"%s\"\n", name, service_name, err)
								return false
							}
							buff.WriteString("\n")
						}
					}
				}
				// services acquired by others
				if len(network.ServicesAcquirable) > 0 {
					buff.WriteString("#########################\n")
					buff.WriteString("## Acquirable Services ##\n")
					buff.WriteString("#########################\n")
					// sort acquirable services so they're deterministic
					sorted2 := []string{}
					for service_name, _ := range network.ServicesAcquirable {
						sorted2 = append(sorted2, service_name)
					}
					sort.Strings(sorted2)
					for _, service_name := range sorted2 {
						buff.WriteString(fmt.Sprintf("### Service: %s\n", service_name))
						// sort acquirable servers so they're deterministic
						sorted3 := []string{}
						for server2, _ := range network.ServicesAcquirable[service_name] {
							sorted3 = append(sorted3, server2)
						}
						sort.Strings(sorted3)
						for _, server2 := range sorted3 {
							for i, rule := range network.ServicesAcquirable[service_name][server2] {
								if i == 0 {
									// only print server for the first rule
									// all of the next variables will be the exact same
									buff.WriteString(fmt.Sprintf("## Source Server: %s\n", rule.Variables.SourceServerName))
									buff.WriteString(fmt.Sprintf("## Source Hostname: %s\n", rule.Variables.SourceServer.Hostname))
									// source service is an optional object
									if rule.Variables.SourceService != nil &&
										rule.Variables.SourceService.Port > 0 {
										buff.WriteString(fmt.Sprintf("## Source IP:Port: %s:%d\n", rule.Variables.SourceNetwork.IP, rule.Variables.SourceService.Port))
									} else {
										buff.WriteString(fmt.Sprintf("## Source IP: %s\n", rule.Variables.SourceNetwork.IP))
									}
								}
								// parse rule
								if err := rule.Rule.ParseServiceAcquirable(buff, rule.Variables); err != nil {
									log.Printf("buildFirewallIPTables(%s) failed to write acquirable service \"%s\" rule: \"%s\"\n", name, service_name, err)
									return false
								}
								buff.WriteString("\n")
							}
						}
					}
				}
				// dependent services
				if len(network.ServiceDependencies) > 0 {
					buff.WriteString("#########################\n")
					buff.WriteString("## Dependency Services ##\n")
					buff.WriteString("#########################\n")
					// sort acquirable services so they're deterministic
					sorted2 := []string{}
					for service_name, _ := range network.ServiceDependencies {
						sorted2 = append(sorted2, service_name)
					}
					sort.Strings(sorted2)
					for _, service_name := range sorted2 {
						buff.WriteString(fmt.Sprintf("### Service: %s\n", service_name))
						// sort acquirable servers so they're deterministic
						sorted3 := []string{}
						for server2, _ := range network.ServiceDependencies[service_name] {
							sorted3 = append(sorted3, server2)
						}
						sort.Strings(sorted3)
						for _, server2 := range sorted3 {
							for i, rule := range network.ServiceDependencies[service_name][server2] {
								if i == 0 {
									// only print the first time
									// all of the next variables will be the exact same
									buff.WriteString(fmt.Sprintf("## Source Server: %s\n", rule.Variables.SourceServerName))
									buff.WriteString(fmt.Sprintf("## Source Hostname: %s\n", rule.Variables.SourceServer.Hostname))
									// source service is an optional object
									if rule.Variables.SourceService != nil &&
										rule.Variables.SourceService.Port > 0 {
										buff.WriteString(fmt.Sprintf("## Source IP:Port: %s:%d\n", rule.Variables.SourceNetwork.IP, rule.Variables.SourceService.Port))
									} else {
										buff.WriteString(fmt.Sprintf("## Source IP: %s\n", rule.Variables.SourceNetwork.IP))
									}
								}
								// parse rule
								if err := rule.Rule.ParseServiceDependencies(buff, rule.Variables); err != nil {
									log.Printf("buildFirewallIPTables(%s) failed to write dependent service \"%s\" rule: \"%s\"\n", name, service_name, err)
									return false
								}
								buff.WriteString("\n")
							}
						}
					}
				}
				// server firewall rules after
				if len(network.RulesAfter) > 0 {
					buff.WriteString("#######################\n")
					buff.WriteString("# Network Rules After #\n")
					buff.WriteString("#######################\n")
					for _, rule := range network.RulesAfter {
						// parse rule
						if err := rule.Rule.ParseNetwork(buff, rule.Variables); err != nil {
							log.Printf("buildFirewallIPTables(%s) failed to write network after \"%s\" rule: \"%s\"\n", name, network_name, err)
							return false
						}
						buff.WriteString("\n")
					}
				}
			}
		}
		if nf {
			// divider newline
			buff.WriteString("\n")
		}
	}
	// server rules before
	if len(fw.ServerRulesAfter) > 0 {
		buff.WriteString("######################\n")
		buff.WriteString("# Server Rules After #\n")
		buff.WriteString("######################\n")
		for _, rule := range fw.ServerRulesAfter {
			// parse rule
			if err := rule.Rule.ParseServer(buff, rule.Variables); err != nil {
				log.Printf("buildFirewallIPTables(%s) failed to write server after rule: \"%s\"\n", name, err)
				return false
			}
			buff.WriteString("\n")
		}
		buff.WriteString("\n")
	}
	// global rules before
	if len(fw.GlobalRulesAfter) > 0 {
		buff.WriteString("######################\n")
		buff.WriteString("# Global Rules After #\n")
		buff.WriteString("######################\n")
		for _, rule := range fw.GlobalRulesAfter {
			// parse rule
			if err := rule.Rule.ParseServer(buff, rule.Variables); err != nil {
				log.Printf("buildFirewallIPTables(%s) failed to write global after rule: \"%s\"\n", name, err)
				return false
			}
			buff.WriteString("\n")
		}
		buff.WriteString("\n")
	}
	// commit
	buff.WriteString("### COMMIT !!!\n\n")
	buff.WriteString("COMMIT\n")
	if _, err := buff.WriteTo(f); err != nil {
		log.Printf("buildFirewallIPTables(%s) failed to write iptables file: \"%s\"\n", name, err)
		return false
	}
	return true
}
