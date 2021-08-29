package firewall

import (
	"log"
)

type Firewall_Variables_Server struct {
	ServerName string    `json:"server-name,omitempty"`
	Server     *Server   `json:"server,omitempty"`
	Firewall   *Firewall `json:"firewall,omitempty"`
}

func (self *Firewall_Variables_Server) IsValid() bool {
	if self == nil {
		log.Println("Firewall_Variables_Server nil")
		return false
	}
	return true
}

type Firewall_Variables_Network struct {
	ServerName  string    `json:"server-name,omitempty"`
	Server      *Server   `json:"server,omitempty"`
	NetworkName string    `json:"network-name,omitempty"`
	Network     *Network  `json:"network,omitempty"`
	Firewall    *Firewall `json:"firewall,omitempty"`
}

func (self *Firewall_Variables_Network) IsValid() bool {
	if self == nil {
		log.Println("Firewall_Variables_Network nil")
		return false
	}
	return true
}

type Firewall_Variables_Service_Passive struct {
	ServerName  string    `json:"server-name,omitempty"`
	Server      *Server   `json:"server,omitempty"`
	NetworkName string    `json:"network-name,omitempty"`
	Network     *Network  `json:"network,omitempty"`
	ServiceName string    `json:"service-name,omitempty"`
	Service     *Service  `json:"service,omitempty"`
	Firewall    *Firewall `json:"firewall,omitempty"`
}

func (self *Firewall_Variables_Service_Passive) IsValid() bool {
	if self == nil {
		log.Println("Firewall_Variables_Service_Passive nil")
		return false
	}
	return true
}

type Firewall_Variables_Service_Acquirable struct {
	ServiceName            string    `json:"service-name,omitempty"`
	SourceServerName       string    `json:"source-server-name,omitempty"`
	SourceServer           *Server   `json:"source-server,omitempty"`
	SourceNetworkName      string    `json:"source-network-name,omitempty"`
	SourceNetwork          *Network  `json:"source-network,omitempty"`
	SourceService          *Service  `json:"source-service,omitempty"`
	DestinationServerName  string    `json:"destination-server-name,omitempty"`
	DestinationServer      *Server   `json:"destination-server,omitempty"`
	DestinationNetworkName string    `json:"destination-network-name,omitempty"`
	DestinationNetwork     *Network  `json:"destination-network,omitempty"`
	DestinationService     *Service  `json:"destination-service,omitempty"`
	Firewall               *Firewall `json:"firewall,omitempty"`
}

func (self *Firewall_Variables_Service_Acquirable) IsValid() bool {
	if self == nil {
		log.Println("Firewall_Variables_Service_Acquirable nil")
		return false
	}
	return true
}

type Firewall_Variables_Service_Dependencies struct {
	ServiceName            string    `json:"service-name,omitempty"`
	SourceServerName       string    `json:"source-server-name,omitempty"`
	SourceServer           *Server   `json:"source-server,omitempty"`
	SourceNetworkName      string    `json:"source-network-name,omitempty"`
	SourceNetwork          *Network  `json:"source-network,omitempty"`
	SourceService          *Service  `json:"source-service,omitempty"`
	DestinationServerName  string    `json:"destination-server-name,omitempty"`
	DestinationServer      *Server   `json:"destination-server,omitempty"`
	DestinationNetworkName string    `json:"destination-network-name,omitempty"`
	DestinationNetwork     *Network  `json:"destination-network,omitempty"`
	DestinationService     *Service  `json:"destination-service,omitempty"`
	Firewall               *Firewall `json:"firewall,omitempty"`
}

func (self *Firewall_Variables_Service_Dependencies) IsValid() bool {
	if self == nil {
		log.Println("Firewall_Variables_Service_Dependencies nil")
		return false
	}
	return true
}
