package snclient

import "github.com/consol-monitoring/snclient/pkg/check_dns"

func init() {
	AvailableChecks["check_dns"] = CheckEntry{"check_dns", NewCheckDNS}
}

func NewCheckDNS() CheckHandler {
	return &CheckBuiltin{
		name:        "check_dns",
		description: "Runs check_dns to perform checks on other snclient agents.",
		check:       check_dns.Check,
	}
}
