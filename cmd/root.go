package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/retlehs/quien/internal/display"
	"github.com/retlehs/quien/internal/resolver"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var jsonFlag bool

var rootCmd = &cobra.Command{
	Use:          "quien [domain or IP]",
	Short:        "A better WHOIS lookup tool",
	Long:         "quien queries WHOIS/RDAP information for a domain or IP address and displays it in a clean, readable format.",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
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
	},
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
		p := tea.NewProgram(m, tea.WithAltScreen())
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

func init() {
	rootCmd.Flags().BoolVar(&jsonFlag, "json", false, "output as JSON")
}

func Execute(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	rootCmd.SetVersionTemplate("quien version {{.Version}}\n")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
