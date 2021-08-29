package firewall

import (
	"encoding/json"
	"fmt"
	"github.com/sabey/unittest"
	"testing"
)

func TestBuild(t *testing.T) {
	fmt.Println("TestBuild")

	// you can build your own object here
	// or you can export your object and build your settings with the executable
	// once built, your files can be found in "settings.BuildPath/firewall"

	// Settings Object
	settings := &Settings{
		BuildPath: "build",
	}
	unittest.NotNil(t, settings)

	// you can also export your objects like so:
	// Settings JSON
	bs, _ := json.Marshal(settings)
	unittest.Equals(t, string(bs), `{"build-path":"build"}`)
	fmt.Printf("Settings: \"%s\"\n", bs)

	// firewall Object
	fw := &Firewall{}
	unittest.NotNil(t, fw)

	// build all
	// fw.Build(settings)

	// build individual server
	// fw.BuildServer(settings, "myserver")

	// firewall JSON
	bs, _ = json.Marshal(fw)
	unittest.Equals(t, string(bs), "{}")
	fmt.Printf("Firewall: \"%s\"\n", bs)
}
