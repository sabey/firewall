package firewall

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"github.com/sabey/unittest"
	"testing"
)

func TestFirewall(t *testing.T) {
	fmt.Println("TestFirewall")
	// settings are optional
	settings := &Settings{
		BuildPath:                 "unittest",
		BuildRemoveFolderHostname: true,
		BuildRemoveFolderHosts:    true,
		BuildRemoveFolderSSH:      true,
		BuildRemoveFolderFirewall: true,
	}
	fw := &Firewall{
		Servers:      make(map[string]*Server),
		FirewallType: FIREWALL_IPTABLES,
		Vars:         make(map[string]interface{}),
		FirewallRulesBefore: []*Firewall_Rule{
			// Flush Rules
			&Firewall_Rule{
				Rule: "-F",
			},
			// Drop Rules
			&Firewall_Rule{
				Rule: "-P INPUT DROP",
			},
			&Firewall_Rule{
				Rule: "-P FORWARD DROP",
			},
			&Firewall_Rule{
				Rule: "-P OUTPUT DROP",
			},
			// local routing
			&Firewall_Rule{
				// allow loopback traffic on your server.
				Rule: "-A INPUT -i lo -j ACCEPT",
			},
			&Firewall_Rule{
				// accepts all established inbound connections
				Rule: "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
			},
			&Firewall_Rule{
				// allows all outbound traffic
				Rule: "-A OUTPUT -j ACCEPT",
			},
			&Firewall_Rule{
				Rule: "# GLOBAL BEFORE: myip: {{.Firewall.Vars.myip}}",
			},
		},
		FirewallRulesAfter: []*Firewall_Rule{
			&Firewall_Rule{
				// allow ping
				Rule: "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT",
			},
			&Firewall_Rule{
				// create a new chain called LOGGING
				Rule: "-N LOGGING",
			},
			&Firewall_Rule{
				// route INPUT to LOGGING chain
				Rule: "-A INPUT -j LOGGING",
			},
			&Firewall_Rule{
				// route OUTPUT to LOGGING chain
				Rule: "-A OUTPUT -j LOGGING",
			},
			&Firewall_Rule{
				// log the packets with this command
				Rule: "-A LOGGING -m limit --limit 5/min -j LOG --log-prefix \"IPTables Packet Dropped: \" --log-level 7",
			},
			&Firewall_Rule{
				// drop the packets
				Rule: "-A LOGGING -j DROP",
			},
			&Firewall_Rule{
				Rule: "# GLOBAL AFTER: myip: {{.Firewall.Vars.myip}}",
			},
		},
	}
	fw.Vars["myip"] = "255.255.255.255"
	// passive services
	// passive services don't support destination networks so we wont check for in-interface
	ssh_passive := &Service{
		Port: 22,
		FirewallRules: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "-A INPUT -p tcp --src {{.Firewall.Vars.myip}} --dport {{.Service.Port}} -j ACCEPT",
			},
			&Firewall_Rule{
				Rule: "# IP: {{.Network.IP}} Port: {{.Service.Port}} MyIP: {{.Firewall.Vars.myip}} MyPubKey: {{.Service.Vars.MYPUBLICKEY}}",
			},
		},
		Vars: make(map[string]interface{}),
	}
	ssh_passive.Vars["MYPUBLICKEY"] = "0a:0b:0c:0d:0e:0f:00:01:02:03:04:05:06:07:08:09"
	http := &Service{
		Port: 80,
		FirewallRules: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "-A INPUT -p tcp --dport {{.Service.Port}} -j ACCEPT",
			},
		},
	}
	https := &Service{
		Port: 443,
		FirewallRules: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "-A INPUT -p tcp --dport {{.Service.Port}} -j ACCEPT",
			},
		},
	}
	// acquirable services
	// acquirable support destination networks so lets check for in-interface
	ssh_acquirable := &Service{
		Port: 22,
		FirewallRules: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "-A INPUT -p tcp --src {{.SourceNetwork.IP}} --dport {{.DestinationService.Port}} -j {{if index .DestinationNetwork.Vars \"in-interface\"}}-i {{.DestinationNetworkName}} {{end}}ACCEPT",
			},
			&Firewall_Rule{
				Rule: "# SourceNetwork.IP: {{.SourceNetwork.IP}} SourceService.Port: {{.SourceService.Port}} DestinationNetwork.IP: {{.DestinationNetwork.IP}} DestinationService.Port: {{.DestinationService.Port}} MyIP: {{.Firewall.Vars.myip}}",
			},
		},
	}
	mysql := &Service{
		Port: 3306,
		FirewallRules: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "-A INPUT -p tcp --src {{.SourceNetwork.IP}} --dport {{.DestinationService.Port}} -j {{if index .DestinationNetwork.Vars \"in-interface\"}}-i {{.DestinationNetworkName}} {{end}}ACCEPT",
			},
		},
	}
	// local media server
	media := &Server{
		Hostname: "media-server",
		Networks: make(map[string]*Network),
		Hosts:    make(map[string][]string),
		SSH:      make(map[string]*SSH),
		FirewallRulesBefore: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "# THIS IS BEFORE",
			},
			&Firewall_Rule{
				Rule: "# SERVER BEFORE: myip: {{.Firewall.Vars.myip}} mymac: {{.Server.Vars.mymac}}",
			},
		},
		FirewallRulesAfter: []*Firewall_Rule{
			&Firewall_Rule{
				Rule: "# THIS IS AFTER",
			},
			&Firewall_Rule{
				Rule: "# SERVER AFTER: myip: {{.Firewall.Vars.myip}} mymac: {{.Server.Vars.mymac}}",
			},
		},
		Vars: map[string]interface{}{
			"mymac": "47:4F:4F:44:34:55",
		},
	}
	media.Networks["lan"] = &Network{
		IP: "192.168.1.31",
		Hosts: []string{
			"tv",
			"movies",
			"pictures",
			"storage",
		},
		ServicesPassive:     make(map[string]*Service),
		ServicesAcquirable:  make(map[string]*Service),
		ServiceDependencies: make(map[string]map[string]map[string]*Service),
		Vars:                make(map[string]interface{}),
	}
	media.Networks["lan"].ServicesPassive["SSH"] = ssh_passive
	media.Networks["lan"].ServicesPassive["HTTP"] = http
	media.Networks["lan"].ServicesPassive["HTTPS"] = https
	media.Networks["lan"].ServicesAcquirable["ssh"] = ssh_acquirable
	media.Networks["lan"].ServicesAcquirable["mysql"] = mysql
	media.Networks["wan"] = &Network{
		IP: "10.0.0.1",
		Hosts: []string{
			"storage",
			"storage.local",
		},
		ServicesPassive:     make(map[string]*Service),
		ServicesAcquirable:  make(map[string]*Service),
		ServiceDependencies: make(map[string]map[string]map[string]*Service),
		Vars:                make(map[string]interface{}),
	}
	media.Networks["wan"].ServicesPassive["ssh"] = ssh_passive
	media.Networks["wan"].ServicesAcquirable["ssh"] = ssh_acquirable
	media.Networks["null"] = &Network{
		IP:                  "127.0.0.0",
		ServicesPassive:     make(map[string]*Service),
		ServicesAcquirable:  make(map[string]*Service),
		ServiceDependencies: make(map[string]map[string]map[string]*Service),
		Vars:                make(map[string]interface{}),
	}
	// reverse http tunnel
	// bind to localhost
	media.SSH["http"] = &SSH{
		User:          "username",
		Host:          "host",
		Key:           "secret_rsa",
		Tunnel:        true,
		TunnelReverse: true,
		LocalHost:     "127.0.0.1",
		LocalPort:     3306,
		RemotePort:    8080,
	}
	fw.Servers["MediaServer"] = media
	// local pc
	home := &Server{
		Hostname: "home",
		Networks: make(map[string]*Network),
		Hosts:    make(map[string][]string),
		HostsBefore: `
		# sometimes, we're going to need some comments
127.0.0.4 and we don't care about the parser

`,
		HostsAfter: `

stuff`,
		HostsDependencies: make(map[string][]string),
		SSH:               make(map[string]*SSH),
		Vars:              make(map[string]interface{}),
	}
	home.Hosts["127.0.0.0"] = []string{
		"mysql",
		"memcache",
		"redis",
		"phpmyadmin",
		"postgresql",
		"rethinkdb",
	}
	home.Hosts["127.0.0.1"] = []string{
		"mypc",
	}
	home.Hosts["127.0.0.2"] = []string{
		"pc",
		junk(hosts_maxlen),
		"not really max per line currently, that's fine",
	}
	home.Networks["lan"] = &Network{
		IP:                  "192.168.1.13",
		ServicesPassive:     make(map[string]*Service),
		ServicesAcquirable:  make(map[string]*Service),
		ServiceDependencies: make(map[string]map[string]map[string]*Service),
		Vars: map[string]interface{}{
			"in-interface": true,
		},
	}
	home.Networks["lan"].ServicesPassive["SSH"] = ssh_passive
	home.Networks["lan"].ServiceDependencies["MediaServer"] = make(map[string]map[string]*Service)
	home.Networks["lan"].ServiceDependencies["MediaServer"]["lan"] = make(map[string]*Service)
	ssh_dependency := &Service{
		// when we acquire this service we're going to set our source port just incase
		Port: 22,
		FirewallRules: []*Firewall_Rule{
			&Firewall_Rule{
				// we're also going to set a rule when we acquire the ssh dependency, we will also mutually share our local ssh server with our dependency
				Rule: "-A INPUT -p tcp --src {{.SourceNetwork.IP}} --dport {{.DestinationService.Port}} -j {{if index .DestinationNetwork.Vars \"in-interface\"}}-i {{.DestinationNetworkName}} {{end}}ACCEPT",
			},
		},
	}
	home.Networks["lan"].ServiceDependencies["MediaServer"]["lan"]["ssh"] = ssh_dependency
	home.Networks["lan"].ServiceDependencies["MediaServer"]["lan"]["mysql"] = nil
	home.HostsDependencies["MediaServer"] = []string{
		"lan",
		"wan",
		"null",
	}
	home.SSH["ssh"] = &SSH{
		User: "username",
		Host: "host",
	}
	// mysql local tunnel
	// bind to localhost
	home.SSH["mysql"] = &SSH{
		User:       "username",
		Host:       "host",
		Key:        "secret_rsa",
		Tunnel:     true,
		LocalHost:  "localhost",
		LocalPort:  3306,
		RemoteHost: "127.0.0.1",
		RemotePort: 3306,
	}
	fw.Servers["MyPC"] = home

	// remote server
	remote := &Server{
		Hostname: "remote",
		Networks: map[string]*Network{
			"public": &Network{
				IP: "0.0.0.0",
				ServicesPassive: map[string]*Service{
					"http":  http,
					"https": https,
				},
				ServicesAcquirable: map[string]*Service{
					"ssh": ssh_acquirable,
				},
				ServiceDependencies: make(map[string]map[string]map[string]*Service),
				Vars:                make(map[string]interface{}),
			},
			"private": &Network{
				IP: "127.0.0.10",
				ServicesAcquirable: map[string]*Service{
					"mysql": mysql,
				},
				Vars: map[string]interface{}{
					"hello": "goodbye",
				},
			},
		},
		Vars: make(map[string]interface{}),
	}
	remote.Networks["private"].FirewallRulesBefore = []*Firewall_Rule{
		&Firewall_Rule{
			Rule: "# NETWORK BEFORE: IP: {{.Network.IP}} MyIP: {{.Firewall.Vars.myip}} Hello? {{.Network.Vars.hello}}",
		},
	}
	remote.Networks["private"].FirewallRulesAfter = []*Firewall_Rule{
		&Firewall_Rule{
			Rule: "# NETWORK AFTER: IP: {{.Network.IP}} MyIP: {{.Firewall.Vars.myip}} Hello? {{.Network.Vars.hello}}",
		},
	}
	remote.Networks["public"].ServiceDependencies["MediaServer"] = make(map[string]map[string]*Service)
	remote.Networks["public"].ServiceDependencies["MediaServer"]["lan"] = make(map[string]*Service)
	remote.Networks["public"].ServiceDependencies["MediaServer"]["lan"]["ssh"] = ssh_dependency
	fw.Servers["remote"] = remote

	// solo server
	solo := &Server{
		Hostname: "solo",
		Networks: map[string]*Network{
			"public": &Network{
				IP:   "0.0.0.0",
				Vars: make(map[string]interface{}),
			},
			"private": &Network{
				IP:   "127.0.0.150",
				Vars: make(map[string]interface{}),
			},
		},
		Vars: make(map[string]interface{}),
	}
	fw.Servers["solo"] = solo

	// build
	unittest.Equals(t, fw.Build(settings), true)


	// compare output, make sure its deterministic

	// Hostname

	// MyPC
	first, err := ioutil.ReadFile(fmt.Sprintf("%s/MyPC.hostname", fw.pathHostname(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err := ioutil.ReadFile(fmt.Sprintf("%s/../../results/hostname/MyPC.hostname", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// MediaServer
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MediaServer.hostname", fw.pathHostname(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/hostname/MediaServer.hostname", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)



	// Hosts

	// MyPC
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MyPC.hosts", fw.pathHosts(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/hosts/MyPC.hosts", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// MediaServer
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MediaServer.hosts", fw.pathHosts(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/hosts/MediaServer.hosts", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)

	// SSH

	// MyPC-mysql
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MyPC-mysql.sh", fw.pathSSH(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/ssh/MyPC-mysql.sh", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// MyPC-ssh
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MyPC-ssh.sh", fw.pathSSH(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/ssh/MyPC-ssh.sh", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// MediaServer-http
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MediaServer-http.sh", fw.pathSSH(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/ssh/MediaServer-http.sh", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)

	// Firewall

	// MyPC
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MyPC.iptables", fw.pathFirewall(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/firewall/MyPC.iptables", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// MediaServer
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/MediaServer.iptables", fw.pathFirewall(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/firewall/MediaServer.iptables", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// remote
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/remote.iptables", fw.pathFirewall(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/firewall/remote.iptables", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
	// solo
	first, err = ioutil.ReadFile(fmt.Sprintf("%s/solo.iptables", fw.pathFirewall(settings)))
	unittest.Equals(t, len(first) > 0, true)
	unittest.IsNil(t, err)
	second, err = ioutil.ReadFile(fmt.Sprintf("%s/../../results/firewall/solo.iptables", fw.pathFirewall(settings)))
	unittest.IsNil(t, err)
	unittest.Equals(t, bytes.Equal(first, second), true)
}
func junk(
	i int,
) string {
	if i > 0 {
		bs := make([]byte, 0, i)
		for x := 0; x < i; x++ {
			bs = append(bs, 'a')
		}
		return string(bs)
	}
	return ""
}
