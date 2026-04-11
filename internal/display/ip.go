package display

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/retlehs/quien/internal/rdap"
)

// RenderIPJSON returns IP info as JSON.
func RenderIPJSON(info *rdap.IPInfo) string {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return string(data)
}

// RenderIP returns a lipgloss-styled string for IP RDAP info.
func RenderIP(info *rdap.IPInfo) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle(info.IP))
	b.WriteString("\n")

	if len(info.Hostnames) > 0 {
		b.WriteString(row("Hostname", nsStyle.Render(info.Hostnames[0])))
		for _, h := range info.Hostnames[1:] {
			b.WriteString(row("", nsStyle.Render(h)))
		}
	}
	if info.Network != "" {
		b.WriteString(row("Network", info.Network))
	}
	if info.Name != "" {
		b.WriteString(row("Name", info.Name))
	}
	if info.Type != "" {
		b.WriteString(row("Type", info.Type))
	}
	if info.Org != "" {
		b.WriteString(row("Org", info.Org))
	}
	if len(info.ASN) > 0 {
		b.WriteString(row("ASN", fmt.Sprintf("AS%d", info.ASN[0].ASN)))
		if info.ASN[0].Name != "" {
			b.WriteString(row("ASN Name", info.ASN[0].Name))
		}
	}
	if info.Country != "" {
		b.WriteString(row("Country", info.Country))
	}
	if info.Abuse != "" {
		b.WriteString(row("Abuse", info.Abuse))
	}

	if info.StartAddr != "" && info.EndAddr != "" {
		b.WriteString("\n")
		b.WriteString(section("Range"))
		b.WriteString(row("Start", info.StartAddr))
		b.WriteString(row("End", info.EndAddr))
		b.WriteString(row("Handle", info.Handle))
	}

	if info.BGP != nil {
		b.WriteString("\n")
		b.WriteString(section("BGP"))
		if info.BGP.Prefix != "" {
			b.WriteString(row("Prefix", info.BGP.Prefix))
		}
	} else if info.BGPStatus != "" {
		b.WriteString("\n")
		b.WriteString(section("BGP"))
		b.WriteString(row("Status", info.BGPStatus))
	}

	if info.PeeringDB != nil {
		b.WriteString("\n")
		b.WriteString(section("PeeringDB"))
		if info.PeeringDB.Name != "" {
			b.WriteString(row("Name", info.PeeringDB.Name))
		}
		if info.PeeringDB.NameLong != "" {
			b.WriteString(row("Long Name", info.PeeringDB.NameLong))
		}
		if info.PeeringDB.Website != "" {
			b.WriteString(row("Website", info.PeeringDB.Website))
		}
		if info.PeeringDB.PolicyGeneral != "" {
			b.WriteString(row("Policy", info.PeeringDB.PolicyGeneral))
		}
		if info.PeeringDB.PolicyRatio != "" {
			b.WriteString(row("Ratio", info.PeeringDB.PolicyRatio))
		}
		if info.PeeringDB.PolicyLocs != "" {
			b.WriteString(row("Peering Locs", info.PeeringDB.PolicyLocs))
		}
		if info.PeeringDB.Traffic != "" {
			b.WriteString(row("Traffic", info.PeeringDB.Traffic))
		}
		if info.PeeringDB.IXCount > 0 {
			b.WriteString(row("IX Count", fmt.Sprintf("%d", info.PeeringDB.IXCount)))
		}
		if info.PeeringDB.FacilityCount > 0 {
			b.WriteString(row("Facility Count", fmt.Sprintf("%d", info.PeeringDB.FacilityCount)))
		}
	} else if info.PeeringDBStatus != "" {
		b.WriteString("\n")
		b.WriteString(section("PeeringDB"))
		b.WriteString(row("Status", info.PeeringDBStatus))
	}

	return b.String()
}
