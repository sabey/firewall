package firewall

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

func (self *Firewall) buildSSH(
	settings *Settings,
	name string,
	server *Server,
) bool {
	// loop and create a shell script for each ssh connection
	// we don't have to worry about being deterministic because each is its own file
	for service, ssh := range server.SSH {
		file := fmt.Sprintf("%s/%s-%s.sh", self.pathSSH(settings), name, service)
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Printf("buildSSH(%s) failed to open ssh file: \"%s\"\n", name, err)
			return false
		}
		// putting file in its own function so we can easily defer file closures in a loop
		if !buildSSH(
			f,
			name,
			server,
			service,
			ssh,
		) {
			// failed
			return false
		}
	}
	return true
}
func buildSSH(
	f *os.File,
	name string,
	server *Server,
	service string,
	ssh *SSH,
) bool {
	defer f.Close()
	buff := &bytes.Buffer{}
	buff.WriteString("#!/bin/bash\n")
	buff.WriteString(fmt.Sprintf("### Server: \"%s\"\n", name))
	buff.WriteString("### SSH ")
	if ssh.Tunnel {
		if !ssh.TunnelReverse {
			buff.WriteString("Local Tunnel ")
		} else {
			buff.WriteString("Reverse Tunnel ")
		}
	}
	buff.WriteString(fmt.Sprintf("Shell: \"%s\"\n", service))
	buff.WriteString("ssh")
	// write flags
	for x, flag := range ssh.Flags {
		if x > 0 {
			buff.WriteString(" ")
			buff.WriteString(flag)
		}
	}
	if ssh.Key != "" {
		buff.WriteString(fmt.Sprintf(" -i %s", ssh.Key))
	}
	// write tunnel
	if ssh.Tunnel {
		if !ssh.TunnelReverse {
			// Regular Tunnel
			// For a regular Tunnel use:
			// ssh -L LocalPort:RemoteHost:RemotePort
			buff.WriteString(" -L ")
			if ssh.LocalHost != "" {
				// LocalHost is optional
				buff.WriteString(fmt.Sprintf("%s:", ssh.LocalHost))
			}
			buff.WriteString(fmt.Sprintf("%d:%s:%d", ssh.LocalPort, ssh.RemoteHost, ssh.RemotePort))
		} else {
			// Reverse Tunnel
			// For a Reverse Tunnel use:
			// ssh -R RemotePort:LocalHost:LocalPort
			buff.WriteString(" -R ")
			if ssh.RemoteHost != "" {
				// RemoteHost is optional
				buff.WriteString(fmt.Sprintf("%s:", ssh.RemoteHost))
			}
			buff.WriteString(fmt.Sprintf("%d:%s:%d", ssh.RemotePort, ssh.LocalHost, ssh.LocalPort))
		}
	}
	// write ssh authentication
	buff.WriteString(" ")
	if ssh.User != "" {
		buff.WriteString(fmt.Sprintf("%s@", ssh.User))
	}
	buff.WriteString(fmt.Sprintf("%s", ssh.Host))
	if ssh.Port > 0 {
		buff.WriteString(fmt.Sprintf(" -p %d", ssh.Port))
	}
	buff.WriteString("\n")
	if _, err := buff.WriteTo(f); err != nil {
		log.Printf("buildSSH(%s) failed to write ssh file: \"%s\"\n", name, err)
		return false
	}
	return true
}
