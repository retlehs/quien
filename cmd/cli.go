package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/retlehs/quien/internal/dnsutil"
	"github.com/retlehs/quien/internal/mail"
)

const longDescription = "Inspect a domain or IP across registration (WHOIS/RDAP), DNS, mail authentication (SPF/DMARC/DKIM/BIMI), TLS, HTTP, SEO, and tech stack — interactive TUI by default, JSON via subcommands."

// command is a subcommand taking exactly one domain-or-IP argument.
type command struct {
	name    string
	aliases []string
	short   string
	run     func(args []string) error
}

var commands []*command

func register(c *command) {
	commands = append(commands, c)
}

func findCommand(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
		if slices.Contains(c.aliases, name) {
			return c
		}
	}
	return nil
}

// stringSliceFlag is repeatable and comma-split, like pflag's StringSliceVar.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	for p := range strings.SplitSeq(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

// parseInterspersed re-parses after each positional so flags may appear
// before or after the subcommand and domain (stdlib flag otherwise stops
// at the first positional).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "%s\n\nUsage:\n  quien [domain or IP] [flags]\n  quien [command]\n\nAvailable Commands:\n", longDescription)

	type entry struct{ name, short string }
	entries := []entry{{"help", "Help about quien"}}
	for _, c := range commands {
		short := c.short
		if len(c.aliases) > 0 {
			short += " (alias: " + strings.Join(c.aliases, ", ") + ")"
		}
		entries = append(entries, entry{c.name, short})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	for _, e := range entries {
		fmt.Fprintf(w, "  %-12s%s\n", e.name, e.short)
	}

	fmt.Fprintf(w, `
Flags:
      --dkim-selector strings   DKIM selector(s) to probe in addition to the built-in common list (repeatable, comma-separated). Overrides %s
  -h, --help                    help for quien
      --json                    output as JSON
      --resolver string         DNS resolver to use for DNS/mail lookups (host or host:port). Overrides %s
  -v, --version                 version for quien
`, mail.DKIMSelectorsEnvVar, dnsutil.ResolverEnvVar)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}

func Execute(version, commit, date string) {
	fs := flag.NewFlagSet("quien", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var dkim stringSliceFlag
	var showVersion, showHelp bool
	fs.BoolVar(&jsonFlag, "json", false, "")
	fs.StringVar(&resolverFlag, "resolver", "", "")
	fs.Var(&dkim, "dkim-selector", "")
	fs.BoolVar(&showVersion, "version", false, "")
	fs.BoolVar(&showVersion, "v", false, "")
	fs.BoolVar(&showHelp, "help", false, "")
	fs.BoolVar(&showHelp, "h", false, "")

	pos, err := parseInterspersed(fs, os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(os.Stdout)
			return
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr, `Run "quien --help" for usage.`)
		os.Exit(1)
	}
	if showHelp {
		printUsage(os.Stdout)
		return
	}
	if showVersion {
		fmt.Printf("quien version %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	dkimSelectorFlag = dkim

	if err := preRun(); err != nil {
		fail(err)
	}

	if len(pos) > 0 {
		if pos[0] == "help" {
			printUsage(os.Stdout)
			return
		}
		if c := findCommand(pos[0]); c != nil {
			if got := len(pos) - 1; got != 1 {
				fail(fmt.Errorf("accepts 1 arg(s), received %d", got))
			}
			if err := c.run(pos[1:]); err != nil {
				fail(err)
			}
			return
		}
	}

	if len(pos) > 1 {
		fail(fmt.Errorf("accepts at most 1 arg(s), received %d", len(pos)))
	}
	if err := runRoot(pos); err != nil {
		fail(err)
	}
}
