package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/retlehs/quien/internal/display"
	"github.com/retlehs/quien/internal/dnsutil"
	"github.com/retlehs/quien/internal/mail"
	"github.com/retlehs/quien/internal/resolver"
	"golang.org/x/term"
)

var jsonFlag bool
var resolverFlag string
var dkimSelectorFlag []string

// preRun applies the persistent flags before any command runs.
func preRun() error {
	if len(dkimSelectorFlag) > 0 {
		if err := os.Setenv(mail.DKIMSelectorsEnvVar, strings.Join(dkimSelectorFlag, ",")); err != nil {
			return err
		}
	}

	if resolverFlag != "" {
		normalized, err := dnsutil.NormalizeResolver(resolverFlag)
		if err != nil {
			return fmt.Errorf("invalid --resolver: %w", err)
		}
		return os.Setenv(dnsutil.ResolverEnvVar, normalized)
	}

	if envResolver := strings.TrimSpace(os.Getenv(dnsutil.ResolverEnvVar)); envResolver != "" {
		normalized, err := dnsutil.NormalizeResolver(envResolver)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", dnsutil.ResolverEnvVar, err)
		}
		return os.Setenv(dnsutil.ResolverEnvVar, normalized)
	}

	return nil
}

func runRoot(args []string) error {
	// No args — show interactive prompt
	if len(args) == 0 {
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			return fmt.Errorf("no domain or IP provided")
		}
		prompt := display.NewPromptModel()
		p := tea.NewProgram(prompt)
		result, err := p.Run()
		if err != nil {
			return err
		}
		pm := result.(display.PromptModel)
		input, isIP, submitted := pm.Result()
		if !submitted {
			return nil
		}
		return runLookup(input, isIP)
	}

	input := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(args[0])), ".")

	isIP := net.ParseIP(input) != nil

	if jsonFlag {
		if isIP {
			info, err := resolver.LookupIP(input)
			if err != nil {
				return fmt.Errorf("IP lookup failed: %w", err)
			}
			fmt.Println(display.RenderIPJSON(info))
		} else {
			info, err := resolver.Lookup(input)
			if err != nil {
				return fmt.Errorf("lookup failed: %w", err)
			}
			fmt.Println(display.RenderJSON(*info))
		}
		return nil
	}

	return runLookup(input, isIP)
}

func runLookup(input string, isIP bool) error {
	if !isIP {
		if _, err := resolver.RegistrableDomain(input); err != nil {
			return err
		}
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		var m display.Model
		if isIP {
			m = display.NewIPModel(input)
		} else {
			m = display.NewModel(input)
		}
		p := tea.NewProgram(m)
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("interactive mode failed: %w", err)
		}
		return nil
	}

	// Non-interactive fallback
	if isIP {
		info, err := resolver.LookupIP(input)
		if err != nil {
			return fmt.Errorf("IP lookup failed: %w", err)
		}
		fmt.Println(display.RenderIP(info))
	} else {
		info, err := resolver.Lookup(input)
		if err != nil {
			return fmt.Errorf("lookup failed: %w", err)
		}
		display.Render(*info)
	}
	return nil
}
