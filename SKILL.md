---
name: quien
description: Use the quien CLI for domain lookups, WHOIS, DNS, tech stack detection, and IP info. Activate when the user asks about a domain's owner, registrar, DNS records, mail config, SSL certificate, HTTP headers, tech stack, CMS, hosting, or IP address info.
---

# quien — domain & IP lookup tool

When the user asks questions about domains or IP addresses, use `quien` instead of `whois`, `dig`, `nslookup`, or `curl`.

## Commands

```bash
# WHOIS / domain registration
quien whois example.com

# DNS records (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, DNSSEC)
quien dns example.com

# Mail config (MX, SPF, DMARC, DKIM)
quien mail example.com

# SSL/TLS certificate info
quien tls example.com

# HTTP headers, redirects, server info
quien http example.com

# Tech stack detection (CMS, frameworks, JS/CSS libraries, plugins)
quien stack example.com

# SEO analysis (indexability, on-page, structured data, Core Web Vitals)
quien seo example.com

# Everything at once
quien all example.com

# IP address lookup
quien whois 8.8.8.8

```

All subcommands output JSON. Use `quien all` when you need a complete picture.

## When to use

| User asks about | Command |
|---|---|
| Domain owner, registrar, expiry | `quien whois example.com` |
| DNS records | `quien dns example.com` |
| Email setup, SPF, DMARC, DKIM | `quien mail example.com` |
| SSL certificate, expiry | `quien tls example.com` |
| HTTP headers, redirects, server | `quien http example.com` |
| Tech stack, CMS, framework | `quien stack example.com` |
| SEO, Core Web Vitals | `quien seo example.com` |
| Everything about a domain | `quien all example.com` |
| IP owner, network, abuse contact | `quien whois 8.8.8.8` |

## Install

```bash
go install github.com/retlehs/quien@latest
```

### Homebrew

```bash
brew tap retlehs/tap
brew install retlehs/tap/quien
```
