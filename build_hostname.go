package firewall

import (
	"fmt"
	"log"
	"os"
)

func (self *Firewall) buildHostname(
	settings *Settings,
	name string,
	server *Server,
) bool {
	file := fmt.Sprintf("%s/%s.hostname", self.pathHostname(settings), name)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("buildHostname(%s) failed to open hostname file: \"%s\"\n", name, err)
		return false
	}
	defer f.Close()
	if _, err := f.Write([]byte(server.Hostname + "\n")); err != nil {
		log.Printf("buildHostname(%s) failed to write hostname file: \"%s\"\n", name, err)
		return false
	}
	return true
}
