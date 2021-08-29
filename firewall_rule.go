package firewall

import (
	"io"
	"log"
	"text/template"
)

type Firewall_Rule struct {
	Rule string `json:"rule,omitempty"`
}

func (self *Firewall_Rule) IsValid() bool {
	if self == nil {
		log.Println("Firewall_Rule nil")
		return false
	}
	if self.Rule == "" {
		log.Println("Firewall_Rule.Rule empty")
		return false
	}
	return true
}
func (self *Firewall_Rule) ParseServer(
	w io.Writer,
	vars *Firewall_Variables_Server,
) error {
	t, err := template.New("rule").Parse(self.Rule)
	if err != nil {
		// rule failed
		log.Printf("Firewall_Rule.ParseServer failed to parse: \"%s\"\n", err)
		return err
	}
	// WE MUST FAIL ON ANY TEMPLATE ERROR!!!
	t.Option("missingkey=error")
	return t.Execute(w, vars)
}
func (self *Firewall_Rule) ParseNetwork(
	w io.Writer,
	vars *Firewall_Variables_Network,
) error {
	t, err := template.New("rule").Parse(self.Rule)
	if err != nil {
		// rule failed
		log.Printf("Firewall_Rule.ParseNetwork failed to parse: \"%s\"\n", err)
		return err
	}
	// WE MUST FAIL ON ANY TEMPLATE ERROR!!!
	t.Option("missingkey=error")
	return t.Execute(w, vars)
}
func (self *Firewall_Rule) ParseServicePassive(
	w io.Writer,
	vars *Firewall_Variables_Service_Passive,
) error {
	t, err := template.New("rule").Parse(self.Rule)
	if err != nil {
		// rule failed
		log.Printf("Firewall_Rule.ParseServicePassive failed to parse: \"%s\"\n", err)
		return err
	}
	// WE MUST FAIL ON ANY TEMPLATE ERROR!!!
	t.Option("missingkey=error")
	return t.Execute(w, vars)
}
func (self *Firewall_Rule) ParseServiceAcquirable(
	w io.Writer,
	vars *Firewall_Variables_Service_Acquirable,
) error {
	t, err := template.New("rule").Parse(self.Rule)
	if err != nil {
		// rule failed
		log.Printf("Firewall_Rule.ParseServiceAcquirable failed to parse: \"%s\"\n", err)
		return err
	}
	// WE MUST FAIL ON ANY TEMPLATE ERROR!!!
	t.Option("missingkey=error")
	return t.Execute(w, vars)
}
func (self *Firewall_Rule) ParseServiceDependencies(
	w io.Writer,
	vars *Firewall_Variables_Service_Dependencies,
) error {
	t, err := template.New("rule").Parse(self.Rule)
	if err != nil {
		// rule failed
		log.Printf("Firewall_Rule.ParseServiceDependencies failed to parse: \"%s\"\n", err)
		return err
	}
	// WE MUST FAIL ON ANY TEMPLATE ERROR!!!
	t.Option("missingkey=error")
	return t.Execute(w, vars)
}
