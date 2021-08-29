package firewall

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func (self *Firewall) Build(
	settings *Settings,
) bool {
	if !self.IsValid() {
		log.Println("Build(): firewall invalid")
		return false
	}
	if !self.buildPath(
		settings,
	) {
		log.Println("Build(): failed to build path")
		return false
	}
	for name, server := range self.Servers {
		if !self.buildServer(
			settings,
			name,
			server,
		) {
			log.Printf("Build(): firewall.Server[%s] failed to build\n", name)
			return false
		}
	}
	return true
}
func (self *Firewall) BuildServer(
	settings *Settings,
	server string,
) bool {
	if !self.IsValid() {
		log.Printf("BuildServer(%s): firewall invalid\n", server)
		return false
	}
	if _, ok := self.Servers[server]; !ok {
		log.Printf("BuildServer(%s): Server not found\n", server)
		return false
	}
	if !self.buildPath(
		settings,
	) {
		log.Printf("BuildServer(%s): failed to build path\n", server)
		return false
	}
	return self.buildServer(
		settings,
		server,
		self.Servers[server],
	)
}
func (self *Firewall) buildServer(
	settings *Settings,
	name string,
	server *Server,
) bool {
	// check our firewall
	if !self.isFirewallValid(
		name,
		server,
	) {
		log.Printf("buildServer(%s): Firewall is Invalid\n", name)
		return false
	}
	// build
	if !self.buildHostname(
		settings,
		name,
		server,
	) {
		log.Printf("buildServer(%s): Failed to Build Hostname\n", name)
		return false
	}
	if !self.buildHosts(
		settings,
		name,
		server,
	) {
		log.Printf("buildServer(%s): Failed to Build Hosts\n", name)
		return false
	}
	if !self.buildSSH(
		settings,
		name,
		server,
	) {
		log.Printf("buildServer(%s): Failed to Build SSH\n", name)
		return false
	}
	fw := self.buildFirewall(
		name,
		server,
	)
	if fw == nil {
		log.Printf("buildServer(%s): Failed to Build Firewall\n", name)
		return false
	}
	if self.FirewallType == FIREWALL_IPTABLES {
		if !self.buildFirewallIPTables(
			settings,
			name,
			server,
			fw,
		) {
			log.Printf("buildServer(%s): Failed to Build Firewall: IPTables\n", name)
			return false
		}
	} else {
		log.Printf("buildServer(%s): Unknown Firewall Type\n", name)
	}
	return true
}
func (self *Firewall) buildPath(
	settings *Settings,
) bool {
	// create buildpath
	path := self.pathBase(settings)
	if path == "" {
		log.Println("Save(): path was empty")
		return false
	}
	// make paths
	os.Mkdir(self.pathBase(settings), 0755)
	// firewall
	os.Mkdir(self.pathfirewall(settings), 0755)
	// hostname
	if settings.IsValid() && settings.BuildRemoveFolderHostname {
		// remove old files
		os.RemoveAll(self.pathHostname(settings))
	}
	os.Mkdir(self.pathHostname(settings), 0755)
	// hosts
	if settings.IsValid() && settings.BuildRemoveFolderHosts {
		os.RemoveAll(self.pathHosts(settings))
	}
	os.Mkdir(self.pathHosts(settings), 0755)
	// ssh
	if settings.IsValid() && settings.BuildRemoveFolderSSH {
		os.RemoveAll(self.pathSSH(settings))
	}
	os.Mkdir(self.pathSSH(settings), 0755)
	// firewall
	if settings.IsValid() && settings.BuildRemoveFolderFirewall {
		os.RemoveAll(self.pathFirewall(settings))
	}
	os.Mkdir(self.pathFirewall(settings), 0755)
	return true
}
func (self *Firewall) pathBase(
	settings *Settings,
) string {
	if settings.IsValid() {
		return filepath.Base(settings.BuildPath)
	}
	return "."
}
func (self *Firewall) pathfirewall(
	settings *Settings,
) string {
	return fmt.Sprintf("./%s/firewall", self.pathBase(settings))
}
func (self *Firewall) pathHostname(
	settings *Settings,
) string {
	return fmt.Sprintf("./%s/hostname", self.pathfirewall(settings))
}
func (self *Firewall) pathHosts(
	settings *Settings,
) string {
	return fmt.Sprintf("./%s/hosts", self.pathfirewall(settings))
}
func (self *Firewall) pathSSH(
	settings *Settings,
) string {
	return fmt.Sprintf("./%s/ssh", self.pathfirewall(settings))
}
func (self *Firewall) pathFirewall(
	settings *Settings,
) string {
	return fmt.Sprintf("./%s/firewall", self.pathfirewall(settings))
}
