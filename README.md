# quien

A better WHOIS lookup tool. Interactive TUI with tabbed views for WHOIS, DNS, mail, SSL/TLS, HTTP headers, and tech stack detection.

![quien demo](demo.gif)

## Install

```
brew tap retlehs/tap
brew install retlehs/tap/quien
```

Or with Go:

```
go install github.com/retlehs/quien@latest
```

## Usage

```
# Interactive prompt
quien

# Domain lookup (interactive TUI)
quien example.com

# IP address lookup
quien 8.8.8.8

# JSON output
quien --json example.com
```

## Features

- **RDAP-first lookups** with WHOIS fallback for broad TLD coverage
- **IANA referral** for automatic WHOIS server discovery
- **Tech stack detection** including WordPress plugins, JS/CSS frameworks, and external services parsed from HTML
- **IP lookups** with reverse DNS, network info, abuse contacts, and ASN discovery via RDAP
- **BGP fallback** for origin ASN/prefix when RDAP does not include ASN data
- **PeeringDB enrichment** for ASN context (network/org, peering policy, peering locations, traffic profile, IX/facility counts)
- **Automatic retry** with exponential backoff on all lookups
- **JSON subcommands** for scripting: `quien dns`, `quien mail`, `quien tls`, `quien http`, `quien stack`, `quien all`

> **Tip:** If you want `quien` to replace your default WHOIS tool, you can add an alias to your shell config:
> ```sh
> alias whois=quien
> ```

## Agent skill

Add quien as a [agent skill](https://skills.sh/) so agents use it for domain and IP lookups:

```
npx skills add retlehs/quien
```
