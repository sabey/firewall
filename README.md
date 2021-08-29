**Contextual Network Templating Engine**

Manage Network Services and Dependencies for:
* **Firewalls**:
  * Contextual firewall rule templating
    * Templating using https://golang.org/pkg/text/template/
    * Individual firewall rules have access to the context and variables of the Source and Destination Server, Network, and Service
    * **you still have to write your own firewall rules, but you will have the necessary context and variables when doing so**
  * Currently supports:
    * iptables
    * other firewalls to be supported!
* **/etc/hostname**
  * just prints your hostname (:
* **/etc/hosts**
  * Generate /etc/hosts with the option of including external /etc/hosts dependencies
* **SSH Tunnels**
  * SSH connection shell scripts with support for Local and Remote port forwarding


A buildable executable and example json files can be found in the `firewall/` folder. You can optionally build your own configuration in the `build_test.go` file and generate the output with `go test`

Binary Flags:
```
settings-input: Raw JSON input
settings-file: Location of JSON file
firewall-input: Raw JSON input
firewall-file: Location of JSON file
server: If specified, only the server is generated, otherwise all servers are generated
```

## Objects:

### Settings
any program variables will be found here
#### Attributes
```
  // firewall/ is appended to this relative or absolute path
BuildPath string  `json:"build-path"`
  // should the firewall/hostname folder be deleted before generating?
BuildRemoveFolderHostname bool  `json:"build-remove-folder-hostname"`
  // should the firewall/hosts folder be deleted before generating?
BuildRemoveFolderHosts  bool  `json:"build-remove-folder-hosts"`
  // should the firewall/ssh folder be deleted before generating?
BuildRemoveFolderSSH  bool  `json:"build-remove-folder-ssh"`
  // should the firewall/firewall folder be deleted before generating?
BuildRemoveFolderFirewall bool  `json:"build-remove-folder-firewall"`
```
#### Example
```
{
  "build-path": "unittest",
  "build-remove-folder-hostname": true,
  "build-remove-folder-hosts": true,
  "build-remove-folder-ssh": true,
  "build-remove-folder-firewall": true
}
```

### firewall
This is the global container object. This contains a list of Servers, Firewall Type and Rules, and Global Variables. Firewall Rules Before/After are generated at the very start and very end of the firewall generation process.
#### Attributes
```
  // Servers
  // [ServerName]*ServerObject
Servers map[string]*Server  `json:"servers"`
  // Global Firewall Rules
  // list of types can be found in `firewall.go`
  // 1 can be used for iptables
FirewallType  int `json:"firewall-type"`
  // Before Server.FirewallRulesBefore
FirewallRulesBefore []*Firewall_Rule  `json:"firewall-rules-before"`
  // After Server.FirewallRulesAfter
FirewallRulesAfter  []*Firewall_Rule  `json:"firewall-rules-after"`
  // Global Variables
Vars  map[string]interface{}  `json:"vars"`
```
#### Functions

```
  // generate all servers
(self *Firewall) Build(settings *Settings)
  // generate an individual server
(self *Firewall) BuildServer(settings *Settings, server string)
```

#### Example
```
{
  "servers": {
    "MediaServer": null
  },
  "firewall-type": 1,
  "firewall-rules-before": [
    {
      "rule": "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT"
    },
    {
      "rule": "# GLOBAL BEFORE: myip: {{.firewall.Vars.myip}}"
    }
  ],
  "firewall-rules-after": [
    {
      "rule": "# GLOBAL AFTER: myip: {{.firewall.Vars.myip}}"
    }
  ],
  "vars": {
    "myip": "255.255.255.255"
  }
}
```


### Server
Server contains mostly local variables, HostsDependencies is the only exception. HostsDependencies can reference another Servers Network and locally include that Networks /etc/hosts. SSH is currently only local and is not referenced by others. SSH is used to generate shell scripts for connecting to other servers. Server Firewall Rules are run in between the firewall  firewall before/after rules. Networks contains our available Networks, each with their own IP, /etc/hosts, and Services. Networks will be frequently referenced by other Servers.
#### Attributes

```
  // Hostname is used for our /etc/hostname and /etc/hosts
Hostname string `json:"hostname"`
  // Additional Local Hosts are appended to our /etc/hosts
  // this appears locally only
  // [IP][]Host
Hosts map[string][]string `json:"hosts"`
  // Hosts Custom Blob of Text Before
  // this appears locally only
HostsBefore string `json:"hosts-before"`
  // Hosts Custom Blob of Text After
  // this appears locally only
HostsAfter string `json:"hosts-after"`
  // Optional Hosts Dependencies
  // Additional referenced Hosts are appended to our /etc/hosts
  // if we reference another Servers Network, we will include that Networks /etc/hosts locally and point the hosts to that Networks IP
  // [ServerName][]Network
HostsDependencies map[string][]string `json:"hosts-dependencies"`
  // SSH
  // this will generate a list of ssh commands for possible local or remote tunnels
  // this appears locally only
  // ssh service name are arbitrary and aren't currently referenced
  // [Service]SSH
SSH map[string]*SSH `json:"ssh"`
  // Firewall Rules
  // Before Services
FirewallRulesBefore []*Firewall_Rule `json:"firewall-before"`
  // After Services
FirewallRulesAfter []*Firewall_Rule `json:"firewall-after"`
  // List of our Accessible Networks and their available Services
  // our Firewall rules will be built from our Network relations
  // NetworkName can be used in place of the Interface name
  // the Interface name can be referenced for specific firewall rules
  // [NetworkName]Network
Networks map[string]*Network `json:"networks"`
  // Server Variables
Vars map[string]interface{} `json:"vars"`
```

#### Example
```
{
  "hostname": "home",
  "hosts": {
    "127.0.0.0": [
      "mysql",
      "memcache",
      "redis",
      "phpmyadmin",
      "postgresql",
      "rethinkdb"
    ],
    "127.0.0.1": [
      "mypc"
    ]
  },
  "hosts-before": "# sometimes, we're going to need some comments",
  "hosts-after": "# or we don't care about the parser",
  "hosts-dependencies": {
    "MediaServer": [
      "lan",
      "wan"
    ]
  },
  "ssh": {
    "mysql": {
      "user": "username",
      "host": "host",
      "key": "secret_rsa",
      "tunnel": true,
      "local-host": "localhost",
      "local-port": 3306,
      "remote-host": "127.0.0.1",
      "remote-port": 3306
    }
  },
  "firewall-before": [
    {
      "rule": "# SERVER BEFORE: myip: {{.firewall.Vars.myip}} mymac: {{.Server.Vars.mymac}}"
    }
  ],
  "firewall-after": [
    {
      "rule": "# SERVER AFTER: myip: {{.firewall.Vars.myip}} mymac: {{.Server.Vars.mymac}}"
    }
  ],
  "networks": {
    "lan": null
  }
}
```

### Network
Network is a "network interface" and must have an IP address. Hosts are not included in the parent Servers /etc/hosts, they are only included by another Servers /etc/hosts from their HostsDependencies. Services contain their own Firewall Rules which are parsed in between Firewall Before/After Rules.

**ServicesPassive** are services that are always available on this Network, they do not and can not be included as a dependency by another server. ServicesPassive should be thought of a public HTTP/FTP/Mail service where you want anyone to have access.

**ServicesAcquirable** are services that this Network makes available to other Servers, they are include with their ServiceDependencies. If another server requests a service from this servers ServicesAcquirable, the Service firewall rules will be parsed locally for each Server that requires this dependency. ServicesAcquirable should be thought of a private SSH/Database/Cache service where you only want to grant access to certain other Servers.

**ServiceDependencies** are the services that this Network requires! ServiceDependencies has an OPTIONAL Service object. If the Service object is set, the firewall rules for this object will be parsed locally. This object will also be passed as the Source Service to the Destination Service that is the dependency. The Service Port is also optional, if Port is not set then the Source Port is unknown. ServiceDependencies Service objects should be thought of local rules that are required to import a dependency.
#### Attributes

```
  // Accessible IP
IP string `json:"ip"`
  // []Host
  // Hosts are referenced by other Servers
  // if referenced, hosts are appended to their /etc/hosts
Hosts []string `json:"hosts"`
  // Passive Services
  // passive services will always be available in the firewall rules
  // [ServiceName]Service
ServicesPassive map[string]*Service `json:"services-passive"`
  // Acquirable Services
  // acquirable services will only be available in firewall rules if acquired
  // [ServiceName]Service
ServicesAcquirable map[string]*Service `json:"services-acquirable"`
  // Optional Service Dependencies
  // Acquired Services will set firewall rules in the acquirable Servers firewall rules
  // this Service object here is optional and will be included in this Servers rules
  // [ServerName][NetworkName][ServiceName]Service
ServiceDependencies map[string]map[string]map[string]*Service `json:"service-dependencies"`
  // Before Server.FirewallRulesBefore
FirewallRulesBefore []*Firewall_Rule `json:"firewall-rules-before"`
  // After Server.FirewallRulesAfter
FirewallRulesAfter []*Firewall_Rule `json:"firewall-rules-after"`
  // Network Variables
Vars map[string]interface{} `json:"vars"`
```
#### Example
```
{
  "ip": "192.168.1.31",
  "hosts": [
    "tv",
    "movies",
    "pictures",
    "storage"
  ],
  "services-passive": {
    "HTTP": {
      "port": 80,
      "rules": [
        {
          "rule": "-A INPUT -p tcp --dport {{.Service.Port}} -j ACCEPT"
        }
      ]
    },
    "SSH": {
      "port": 22,
      "rules": [
        {
          "rule": "-A INPUT -p tcp --src {{.firewall.Vars.myip}} --dport {{.Service.Port}} -j ACCEPT"
        },
        {
          "rule": "# IP: {{.Network.IP}} Port: {{.Service.Port}} MyIP: {{.firewall.Vars.myip}} MyPubKey: {{.Service.Vars.MYPUBLICKEY}}"
        }
      ],
      "vars": {
        "MYPUBLICKEY": "0a:0b:0c:0d:0e:0f:00:01:02:03:04:05:06:07:08:09"
      }
    }
  },
  "services-acquirable": {
    "mysql": {
      "port": 3306,
      "rules": [
        {
          "rule": "-A INPUT -p tcp --src {{.SourceNetwork.IP}} --dport {{.DestinationService.Port}} -j {{if index .DestinationNetwork.Vars \"in-interface\"}}-i {{.DestinationNetworkName}} {{end}}ACCEPT"
        }
      ]
    },
    "ssh": {
      "port": 22,
      "rules": [
        {
          "rule": "-A INPUT -p tcp --src {{.SourceNetwork.IP}} --dport {{.DestinationService.Port}} -j {{if index .DestinationNetwork.Vars \"in-interface\"}}-i {{.DestinationNetworkName}} {{end}}ACCEPT"
        },
        {
          "rule": "# SourceNetwork.IP: {{.SourceNetwork.IP}} SourceService.Port: {{.SourceService.Port}} DestinationNetwork.IP: {{.DestinationNetwork.IP}} DestinationService.Port: {{.DestinationService.Port}} MyIP: {{.firewall.Vars.myip}}"
        }
      ]
    }
  },
  "service-dependencies": {
    "MediaServer": {
      "lan": {
        "mysql": null,
        "ssh": {
          "port": 22,
          "rules": [
            {
              "rule": "-A INPUT -p tcp --src {{.SourceNetwork.IP}} --dport {{.DestinationService.Port}} -j {{if index .DestinationNetwork.Vars \"in-interface\"}}-i {{.DestinationNetworkName}} {{end}}ACCEPT"
            }
          ]
        }
      }
    }
  },
  "firewall-rules-before": [
    {
      "rule": "# NETWORK BEFORE: IP: {{.Network.IP}} MyIP: {{.firewall.Vars.myip}} Hello? {{.Network.Vars.hello}}"
    }
  ],
  "firewall-rules-after": [
    {
      "rule": "# NETWORK AFTER: IP: {{.Network.IP}} MyIP: {{.firewall.Vars.myip}} Hello? {{.Network.Vars.hello}}"
    }
  ],
  "vars": {
    "hello": "goodbye"
  }
}
```

### Service
See Network Service attributes for an explanation.
#### Attributes

```
Port          uint16           `json:"port"`
FirewallRules []*Firewall_Rule `json:"rules"`
  // Service Variables
Vars map[string]interface{} `json:"vars"`
```

### Firewall_Rule
Firewall_Rule currently only has a single attribute.
Rule supports Golang text template: https://golang.org/pkg/text/template/
Generate will fail if a template parsing error occurs.
Different Firewall_Variables_* Objects will be passed as context to the Rule when templating.
#### Attributes
```
Rule  string  `json:"rule"`
```

#### Example
```
{
  "rule": "SourceNetwork.IP: {{.SourceNetwork.IP}} SourceService.Port: {{.SourceService.Port}} DestinationNetwork.IP: {{.DestinationNetwork.IP}} DestinationService.Port: {{.DestinationService.Port}} MyIP: {{.firewall.Vars.myip}}"
}
```

### Firewall_Variables_Server
This is passed to Server Firewall Rules
#### Attributes
```
ServerName string      `json:"server-name"`
Server     *Server     `json:"server"`
firewall *Firewall `json:"firewall"`
```

### Firewall_Variables_Network
This is passed to Network Firewall Rules
#### Attributes
```
ServerName string      `json:"server-name"`
Server     *Server     `json:"server"`
NetworkName string      `json:"network-name"`
Network     *Network    `json:"network"`
firewall *Firewall `json:"firewall"`
```

### Firewall_Variables_Service_Passive
This is passed to Passive Services.
Passive services do not have a source, only their own selves which is the destination
#### Attributes
```
ServerName string      `json:"server-name"`
Server     *Server     `json:"server"`
NetworkName string      `json:"network-name"`
Network     *Network    `json:"network"`
ServiceName string      `json:"service-name"`
Service     *Service    `json:"service"`
firewall *Firewall `json:"firewall"`
```

### Firewall_Variables_Service_Acquirable
This is passed to Services that have been acquired by another
#### Attributes
```
ServiceName            string      `json:"service-name"`
SourceServerName       string      `json:"source-server-name"`
SourceServer           *Server     `json:"source-server"`
SourceNetworkName      string      `json:"source-network-name"`
SourceNetwork          *Network    `json:"source-network"`
SourceService          *Service    `json:"source-service"`
DestinationServerName  string      `json:"destination-server-name"`
DestinationServer      *Server     `json:"destination-server"`
DestinationNetworkName string      `json:"destination-network-name"`
DestinationNetwork     *Network    `json:"destination-network"`
DestinationService     *Service    `json:"destination-service"`
firewall             *Firewall `json:"firewall"`
```

### Firewall_Variables_Service_Dependencies
This is passed to Services has that acquired another
#### Attributes
```
ServiceName            string      `json:"service-name"`
SourceServerName       string      `json:"source-server-name"`
SourceServer           *Server     `json:"source-server"`
SourceNetworkName      string      `json:"source-network-name"`
SourceNetwork          *Network    `json:"source-network"`
SourceService          *Service    `json:"source-service"`
DestinationServerName  string      `json:"destination-server-name"`
DestinationServer      *Server     `json:"destination-server"`
DestinationNetworkName string      `json:"destination-network-name"`
DestinationNetwork     *Network    `json:"destination-network"`
DestinationService     *Service    `json:"destination-service"`
firewall             *Firewall `json:"firewall"`
```