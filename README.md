# whoer ip checker

A Node.js script that scrapes [whoer.com](https://whoer.com) for IP intelligence. It pulls every data point the site exposes about an IP address, either your own public IP or any address you feed it, then prints a clean report to your terminal. You can also dump the report to a JSON or text file.

## Aim

I built this because I wanted whoer.com's data without leaving the terminal. No API key, no browser, no copying fields off a web page. Just run it, get the report, move on. It works as a quick OSINT helper, a sanity check when you're testing VPNs or proxies, or a way to feed whoer's fingerprint data into other tools through JSON.

## What it pulls

Every field whoer.com shows on its homepage and on `/ip/<address>/`:

- IP address
- Hostname
- ISP
- ASN (number plus organization)
- Network / CIDR
- IP range
- IP type (residential, hosting, business, etc.)
- Connection type
- IP version (IPv4 or IPv6)
- Country with ISO code
- Region, city, postal
- Continent
- Coordinates (lat/long)
- Timezone
- Local time at the IP
- Operating system
- Browser name plus version
- Full user agent string
- Language / languages
- Do Not Track flag
- Canvas fingerprint
- DNS / proxy DNS
- Anonymous VPN flag
- Public proxy flag
- Anonymizer flag
- Blacklist flag
- ISP score (0 to 10)
- Fraud score (0 to 100, derived from the ISP score with escalation for VPN, proxy, or blacklist hits)

## How it works

Whoer.com is a Nuxt app. It ships a server-rendered payload inside a `__NUXT_DATA__` script tag on every page. The script grabs the HTML, extracts that payload, walks Nuxt's indexed serialization format to resolve all the references, then reshapes the result into a flat report.

No headless browser. No puppeteer. Just `fetch` plus a parser. It's fast.

## Requirements

- Node.js 18 or newer (needs built-in `fetch`)
- Internet access to reach whoer.com

## Install

```bash
git clone https://github.com/krainium/whoer-ip-checker.git
cd whoer
```

That's it. No dependencies to install.

If you want to call it from anywhere:

```bash
chmod +x whoer.js
sudo ln -s "$(pwd)/whoer.js" /usr/local/bin/whoer
```

## Usage

### Interactive menu

Run with no arguments:

```bash
node whoer.js
```

You get a menu:

```
============================================
   Whoer ip checker
============================================
  1) Check MY IP (auto-detect via whoer.com)
  2) Check a specific IP address
  3) Help
  q) Quit
```

Pick an option. If you choose to look up an IP, it asks you for the address. After the report prints, it asks if you want to save it to a file.

### CLI flags

Skip the menu when you already know what you want:

```bash
# Your own public IP
node whoer.js --self

# Any IP address
node whoer.js --ip 8.8.8.8

# Save the report as JSON
node whoer.js --ip 1.1.1.1 -o cloudflare.json

# Save as plain text (ANSI colors stripped)
node whoer.js --ip 8.8.4.4 -o google.txt

# Help
node whoer.js --help
```

### Flag reference

| Flag | Alias | Description |
|------|-------|-------------|
| `--self` | `-s` | Detect and report your own public IP |
| `--ip <ADDR>` | `-i` | Look up a specific IPv4 or IPv6 address |
| `--out <FILE>` | `-o` | Save the report to a file. `.json` saves structured JSON. Any other extension saves plain text |
| `--menu` | `-m` | Force the interactive menu |
| `--help` | `-h` | Show help |

## Example output

```
---------------------------------------------------------
  WHOER.COM  —  IP INTELLIGENCE REPORT
---------------------------------------------------------
  IP Address         8.8.8.8
  Hostname           dns.google
  ISP                Google LLC
  ASN                15169 (Google LLC)
  Network / CIDR     8.8.8.0/24
  IP Type            residential
  IP Version         IPv4
  Country            United States [US]
  Region / Province  California
  City               Mountain View
  Coordinates        37.23249, -121.69627
  Timezone           America/Los_Angeles
  Local Time         2026-04-19 15:55:44
  Anonymous VPN      No
  Public Proxy       No
  Blacklisted        No
  ISP Score          10/10
  Fraud Score        0/100
---------------------------------------------------------
```

## JSON output

When you save with `-o file.json` you get structured data ready to pipe into jq, store in a database, or feed to another tool:

```json
{
  "ip": "1.1.1.1",
  "hostname": "one.one.one.one",
  "isp": "Cloudflare",
  "asn": 13335,
  "asn_organization": "Cloudflare",
  "network": "1.1.1.0/24",
  "ip_type": "hosting",
  "country": "Australia",
  "iso_code": "AU",
  "city": "Sydney",
  "is_anonymous_vpn": false,
  "is_public_proxy": false,
  "is_route_ip_black_list": false,
  "isp_score": 10,
  "fraud_score": 0
}
```

## Quit

- From the menu: type `q`, `quit`, `exit`, or `0`
- From a prompt: press Ctrl-D
- Anywhere: Ctrl-C

## Notes

- Some fields come back empty depending on the IP. Residential IPs usually have rich geo data. Cloud and hosting IPs often lack postal codes, connection type, or hostname. The script marks missing fields as `Unknown` instead of hiding them.
- The fraud score is derived. Whoer itself only reports a 0-to-10 ISP score. The script inverts that to a 0-to-100 risk number and bumps it up when VPN, proxy, or blacklist flags are set. If you want the raw whoer number, look at the `isp_score` field in the JSON output.
- Be polite. Whoer is a free site. Don't hammer it in a loop.

## Contributing

Issues and pull requests welcome at https://github.com/Krainium/whoer-ip-checker
