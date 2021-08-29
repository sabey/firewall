package firewall

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
)

const (
	hosts_maxlen = 1000
)

func (self *Firewall) buildHosts(
	settings *Settings,
	name string,
	server *Server,
) bool {
	file := fmt.Sprintf("%s/%s.hosts", self.pathHosts(settings), name)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("buildHosts(%s) failed to open hosts file: \"%s\"\n", name, err)
		return false
	}
	defer f.Close()
	buff := &bytes.Buffer{}
	// hosts our header
	buff.WriteString(fmt.Sprintf("### Server: \"%s\"\n", name))
	buff.WriteString(fmt.Sprintf("### Hostname: \"%s\"\n", server.Hostname))
	buff.WriteString("### IPs: [")
	// print only unique IPs
	unique := make(map[string]struct{})
	for _, network := range server.Networks {
		unique[network.IP] = struct{}{}
	}
	// this is an extremely basic sort method for ips
	// I only care that the output is deterministic
	// sort ips
	sorted := []string{}
	for ip, _ := range unique {
		sorted = append(sorted, ip)
	}
	sort.Strings(sorted)
	// print all avaliable IPs
	seperate := false
	for _, ip := range sorted {
		if seperate {
			buff.WriteString(", ")
		}
		seperate = true
		buff.WriteString(ip)
	}
	buff.WriteString("]\n")
	// write localhost
	buff.WriteString("127.0.0.1\t\tlocalhost\n")
	// write hosts
	buff.WriteString(fmt.Sprintf("127.0.0.1\t\t%s\n\n", server.Hostname))
	// host blob before
	if server.HostsBefore != "" {
		buff.WriteString("# Hosts Before\n")
		buff.WriteString(server.HostsBefore)
		buff.WriteString("\n\n")
	}
	// custom hosts
	if len(server.Hosts) > 0 {
		buff.WriteString("# Custom Hosts\n")
		// this is an extremely basic sort method for ips
		// I only care that the output is deterministic
		// sort ips
		sorted = []string{}
		for ip, _ := range server.Hosts {
			sorted = append(sorted, ip)
		}
		sort.Strings(sorted)
		for _, ip := range sorted {
			// print hosts
			printHosts(buff, ip, server.Hosts[ip])
		}
		buff.WriteString("\n")
	}
	// acquired hosts
	if len(server.HostsDependencies) > 0 {
		buff.WriteString("# Acquired Hosts\n")
		// sort for a deterministic output
		// sort ips
		sorted = []string{}
		for server_name, _ := range server.HostsDependencies {
			sorted = append(sorted, server_name)
		}
		sort.Strings(sorted)
		for _, server_name := range sorted {
			if name == server_name {
				log.Printf("buildHosts(%s) Acquired Server Name is the same as our Server Name: \"%s\"\n", name, server_name)
				return false
			}
			s, ok := self.Servers[server_name]
			if !ok {
				log.Printf("buildHosts(%s) Acquired Server not found: \"%s\"\n", name, server_name)
				return false
			}
			for _, network := range server.HostsDependencies[server_name] {
				n, ok := s.Networks[network]
				if !ok {
					log.Printf("buildHosts(%s) Acquired Server Network not found: \"%s\" -> \"%s\"\n", name, server_name, network)
					return false
				}
				buff.WriteString(fmt.Sprintf("## Server: \"%s\" Network: \"%s\"\n", server_name, network))
				// print hosts
				if len(n.Hosts) > 0 {
					printHosts(buff, n.IP, n.Hosts)
				}
			}
		}
		buff.WriteString("\n")
	}
	// host blob after
	if server.HostsAfter != "" {
		buff.WriteString("# Hosts After\n")
		buff.WriteString(server.HostsAfter)
		buff.WriteString("\n\n")
	}
	if _, err := buff.WriteTo(f); err != nil {
		log.Printf("buildHosts(%s) failed to write hosts file: \"%s\"\n", name, err)
		return false
	}
	return true
}
func printHosts(
	buff *bytes.Buffer,
	ip string,
	hosts []string,
) {
	l := 0
	f := false
	pip := true
	for _, host := range hosts {
		if l > hosts_maxlen {
			// reset line
			buff.WriteString("\n")
			l = 0
			pip = true
		}
		if pip {
			// write IP
			buff.WriteString(fmt.Sprintf("%s\t\t", ip))
			pip = false
		} else {
			if f {
				// divider space
				buff.WriteString(" ")
			}
		}
		// write host
		l += len(host)
		buff.WriteString(host)
		f = true
	}
	// ip newline divider
	buff.WriteString("\n")
}
