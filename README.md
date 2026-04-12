# quien

A better WHOIS lookup tool. Interactive TUI with tabbed views for WHOIS, DNS, mail, SSL/TLS, HTTP headers, tech stack detection, and SEO analysis.

![quien demo](demo.gif)

## Install

**Homebrew**

```
brew tap retlehs/tap
brew install retlehs/tap/quien
```

**Ubuntu / Debian**

```
curl -fsSL https://apt.quien.dev/install.sh | sudo sh
```

**Go**

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
- **Mail configuration audit** — MX, SPF, DMARC, DKIM, and BIMI with VMC chain validation
- **SEO analysis** — indexability (robots.txt, canonical, sitemap), on-page (title, description, headings, images), structured data (JSON-LD, Open Graph, Twitter Cards), and performance hints (compression, caching, render-blocking resources)
- **Core Web Vitals** — LCP, INP, CLS, FCP, and TTFB field data with historical trends via the CrUX API (optional)
- **Tech stack detection** including WordPress plugins, JS/CSS frameworks, and external services parsed from HTML
- **IP lookups** with reverse DNS, network info, abuse contacts, and ASN discovery via RDAP
- **BGP fallback** for origin ASN/prefix when RDAP does not include ASN data
- **PeeringDB enrichment** for ASN context (network/org, peering policy, peering locations, traffic profile, IX/facility counts)
- **Automatic retry** with exponential backoff on all lookups
- **JSON subcommands** for scripting: `quien dns`, `quien mail`, `quien tls`, `quien http`, `quien seo`, `quien stack`, `quien all`

## Core Web Vitals

The SEO tab includes local checks out of the box. For Core Web Vitals field data (real-user metrics from Chrome), set a CrUX API key:

```sh
export QUIEN_CRUX_API_KEY=your-api-key
```

This enables LCP, INP, CLS, FCP, and TTFB p75 values with good/needs-improvement/poor ratings, plus an 8-25 week trend sparkline.

<details>
<summary>Getting a CrUX API key</summary>

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select an existing one)
3. Go to **APIs & Services > Library**
4. Search for **Chrome UX Report API** and enable it
5. Go to **APIs & Services > Credentials**
6. Click **Create Credentials > API key**
7. Click **Edit API key**, then under **API restrictions** select **Restrict key** and choose **Chrome UX Report API** from the list
8. Copy the key and set it as `QUIEN_CRUX_API_KEY`

The CrUX API is free. Not all domains have field data — a site needs enough Chrome traffic to be included in the Chrome User Experience Report.

</details>

> [!TIP]
> If you want `quien` to replace your default WHOIS tool, you can add an alias to your shell config:
> ```sh
> alias whois=quien
> ```

## Agent skill

Add quien as a [agent skill](https://skills.sh/) so agents use it for domain and IP lookups:

```
npx skills add retlehs/quien
```
