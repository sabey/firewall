package firewall

type Settings struct {
	// Build Options
	BuildPath                 string `json:"build-path,omitempty"`
	BuildRemoveFolderHostname bool   `json:"build-remove-folder-hostname,omitempty"`
	BuildRemoveFolderHosts    bool   `json:"build-remove-folder-hosts,omitempty"`
	BuildRemoveFolderSSH      bool   `json:"build-remove-folder-ssh,omitempty"`
	BuildRemoveFolderFirewall bool   `json:"build-remove-folder-firewall,omitempty"`
}

func (self *Settings) IsValid() bool {
	if self == nil {
		return false
	}
	return true
}
