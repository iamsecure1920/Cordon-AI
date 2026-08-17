# EasyHunt AI — Complete Tool Reference

> **Researched from 53 official GitHub repositories.**
> Deep profiles for 54 of the 82 catalogued tools: what each does, how to install
> it, how to use it, and what it depends on.
> Last updated: 2026-07-30
>
> Not the authoritative catalogue — `easyhunt/tools/common.py` is, and
> `easyhunt doctor` reports what is actually installed and working. The 28 tools
> without a profile here are catalogued and governed like the rest; they just
> have no long-form writeup yet.

---

## Table of Contents

1. [Runtime Requirements](#runtime-requirements)
2. [Installing](#installing)
3. [Master Tool Matrix](#master-tool-matrix) — generated from the install recipes
4. [Detailed Profiles](#detailed-profiles) — purpose and usage, per tool
5. [Critical Notes for Auto-Installation](#critical-notes-for-auto-installation)
6. [API keys](#api-keys)

---

## Runtime Requirements

Install these **first** before any tools.

### Go >= 1.21 (28 tools)
```bash
wget https://go.dev/dl/go1.24.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Python >= 3.10 (14 tools)
```bash
sudo apt install -y python3 python3-pip python3-venv pipx
pipx ensurepath
```

### Rust + Cargo (4 tools)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Node.js >= 20 (2 tools)
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20 && nvm use 20
```

### Ruby 2.x/3.x (1 tool: whatweb)
```bash
sudo apt install -y ruby ruby-dev bundler
```

### System Libraries
```bash
sudo apt install -y libpcap-dev dnsutils whois nmap masscan git curl wget unzip tar
```

---

## Installing

`./bootstrap.sh` installs everything below; `easyhunt install` adds what is
missing and `easyhunt install --core` limits it to the minimum viable
pipeline. The per-tool commands used to be copied into this section by hand,
which is how the matrix below ended up missing 32 tools — the recipes in
`easyhunt/install/recipes.py` are the source of truth and are what actually
runs. Read them there, or run `easyhunt doctor` to see what is working on
this machine.


## Master Tool Matrix

<!-- BEGIN GENERATED TOOL MATRIX -->

**84 installable tools**, generated from `easyhunt/install/recipes.py` by `scripts/gen_tool_matrix.py`.
Do not edit this table by hand — run the script.
`easyhunt doctor` reports which of these are actually working on *this* machine.

| Tool | Category | Install | License | Core |
|------|----------|---------|---------|------|
| `cloud_enum` | cloud | git clone | MIT |  |
| `cloudfox` | cloud | go install | MIT |  |
| `cloudpeass` | cloud | git clone | MIT |  |
| `kubescape` | cloud | release | Apache-2.0 |  |
| `prowler` | cloud | pipx | Apache-2.0 |  |
| `s3scanner` | cloud | go install | MIT |  |
| `aderyn` | contracts | cargo | MIT |  |
| `forge` | contracts | release | Apache-2.0 OR MIT |  |
| `medusa` | contracts | go install | AGPL-3.0 |  |
| `slither` | contracts | pipx | AGPL-3.0 |  |
| `alterx` | dns | go install | MIT |  |
| `cdncheck` | dns | go install | MIT |  |
| `dig` | dns | apt | MPL-2.0 | ✅ |
| `dnsx` | dns | go install | MIT | ✅ |
| `massdns` | dns | git clone | BSD-2-Clause |  |
| `shuffledns` | dns | go install | MIT |  |
| `arjun` | endpoints | pipx | AGPL-3.0 |  |
| `dirsearch` | endpoints | pipx | GPL-2.0 |  |
| `feroxbuster` | endpoints | script | MIT |  |
| `ffuf` | endpoints | go install | MIT | ✅ |
| `gau` | endpoints | go install | MIT | ✅ |
| `gobuster` | endpoints | go install | Apache-2.0 |  |
| `katana` | endpoints | go install | MIT | ✅ |
| `netsanitizer` | endpoints | git clone | MIT |  |
| `paramspider` | endpoints | git clone | MIT |  |
| `waybackurls` | endpoints | go install | MIT | ✅ |
| `waymore` | endpoints | pipx | MIT |  |
| `jaeles` | engine | go install | MIT |  |
| `nuclei` | engine | go install | MIT | ✅ |
| `osmedeus` | engine | script | MIT |  |
| `semgrep` | engine | pipx | LGPL-2.1 |  |
| `strix` | engine | manual | Apache-2.0 |  |
| `commix` | exploit | git clone | GPL-3.0 |  |
| `dalfox` | exploit | go install | MIT | ✅ |
| `interactsh-client` | exploit | go install | MIT |  |
| `nosqli` | exploit | go install | AGPL-3.0 |  |
| `smuggler` | exploit | git clone | MIT |  |
| `smuggler-framework` | exploit | manual | operator-supplied |  |
| `sqlmap` | exploit | pipx | GPL-2.0 | ✅ |
| `ssrfmap` | exploit | git clone | MIT |  |
| `sstimap` | exploit | git clone | GPL-3.0 |  |
| `xsstrike` | exploit | git clone | GPL-3.0 |  |
| `corscanner` | http | pipx | MIT |  |
| `graphql-cop` | http | git clone | MIT |  |
| `httpx` | http | go install | MIT | ✅ |
| `jwt_tool` | http | git clone | GPL-3.0 |  |
| `nikto` | http | git clone | GPL-3.0 |  |
| `testssl` | http | git clone | GPL-2.0 |  |
| `wafw00f` | http | pipx | BSD-3-Clause |  |
| `wapiti` | http | pipx | GPL-2.0 |  |
| `websocat` | http | release | MIT |  |
| `whatweb` | http | apt | GPL-2.0 |  |
| `gf` | js | go install | MIT |  |
| `jsluice` | js | go install | MIT |  |
| `linkfinder` | js | git clone | MIT |  |
| `retire` | js | npm | Apache-2.0 |  |
| `secretfinder` | js | git clone | GPL-3.0 |  |
| `deepteam` | llmsec | pipx | Apache-2.0 |  |
| `garak` | llmsec | pipx | Apache-2.0 |  |
| `promptfoo` | llmsec | npm | MIT |  |
| `masscan` | ports | apt | AGPL-3.0 |  |
| `naabu` | ports | go install | MIT | ✅ |
| `nmap` | ports | apt | NPSL | ✅ |
| `amass` | recon | go install | Apache-2.0 |  |
| `asnmap` | recon | go install | MIT |  |
| `assetfinder` | recon | go install | MIT | ✅ |
| `findomain` | recon | cargo | GPL-3.0 |  |
| `subfinder` | recon | go install | MIT | ✅ |
| `theHarvester` | recon | git clone | GPL-2.0 |  |
| `tlsx` | recon | go install | MIT |  |
| `uncover` | recon | go install | MIT |  |
| `whois` | recon | apt | GPL-2.0+ | ✅ |
| `google-chrome-stable` | runtime | script | proprietary |  |
| `git` | secrets | apt | GPL-2.0 | ✅ |
| `gitdorker` | secrets | git clone | MIT |  |
| `gitleaks` | secrets | go install | MIT | ✅ |
| `kingfisher` | secrets | release | Apache-2.0 | ✅ |
| `noseyparker` | secrets | release | Apache-2.0 |  |
| `trufflehog` | secrets | go install | AGPL-3.0 |  |
| `dnsreaper` | takeover | git clone | AGPL-3.0 |  |
| `subdomainsleuth` | takeover | manual | Apache-2.0 |  |
| `subdominator` | takeover | pipx | MIT |  |
| `subjack` | takeover | go install | MIT |  |
| `subzy` | takeover | go install | GPL-2.0 | ✅ |

**Core** marks the minimum viable pipeline (`easyhunt install --core`).

<!-- END GENERATED TOOL MATRIX -->

---

## Detailed Profiles

---

### subfinder
**GitHub**: https://github.com/projectdiscovery/subfinder  
**Purpose**: Passive subdomain discovery via 40+ sources (crt.sh, VirusTotal, Shodan, SecurityTrails, Censys, etc.)  
**Go Requirement**: >= 1.24  

```bash
# Install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Usage
subfinder -d example.com                      # basic
subfinder -d example.com -o output.txt        # save output
subfinder -dL domains.txt                     # from file
subfinder -d example.com -all                 # all sources (slower, thorough)
subfinder -d example.com -s crtsh,github      # specific sources
subfinder -d example.com -oJ                  # JSON Lines output
subfinder -d example.com -silent              # subdomains only stdout
subfinder -d example.com -pc provider-config.yaml  # with API keys
```

**API Keys** (configure in `~/.config/subfinder/provider-config.yaml`):
- VirusTotal, SecurityTrails, Censys, Shodan, BinaryEdge, Chaos, PassiveTotal

---

### assetfinder
**GitHub**: https://github.com/tomnomnom/assetfinder  
**Purpose**: Lightweight subdomain finder (crt.sh, certspotter, threatcrowd, wayback, Facebook CT)  

```bash
# Install
go install github.com/tomnomnom/assetfinder@latest

# Usage
assetfinder example.com               # all related domains
assetfinder --subs-only example.com   # direct subdomains only
echo "example.com" | assetfinder      # stdin

# Facebook CT module needs:
export FB_APP_ID=your_app_id
export FB_APP_SECRET=your_app_secret
```

---

### findomain
**GitHub**: https://github.com/Findomain/Findomain  
**Purpose**: Rust-based subdomain discovery via Certificate Transparency + APIs. Includes port scan, screenshots, DNS resolution, webhook alerts  
**License**: GPL-3.0  
**Extra Deps**: Chrome (screenshots), PostgreSQL (monitoring mode)  

```bash
# Install
cargo install findomain
# or binary:
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/bin/

# Usage
findomain -t example.com              # basic
findomain -t example.com -o           # save to auto-named file
findomain -f domains.txt -o           # multi-domain from file
findomain -t example.com -i           # resolve IPs
```

---

### amass (OWASP)
**GitHub**: https://github.com/owasp-amass/amass  
**Purpose**: Full attack surface mapping — passive intel + active DNS brute-force + reverse DNS + WHOIS + graph DB  
**License**: Apache-2.0 | **Go**: >= 1.21  

```bash
# Install
go install -v github.com/owasp-amass/amass/v4/...@latest
# or: docker pull caffix/amass

# Usage
amass enum -d example.com              # passive enumeration
amass enum -d example.com -active      # active + passive
amass enum -d example.com -brute       # DNS brute-force
amass intel -asn 15169                 # discover via ASN
amass intel -cidr 104.154.0.0/15       # discover via CIDR
```

---

### asnmap
**GitHub**: https://github.com/projectdiscovery/asnmap  
**Purpose**: Maps organization network ranges via ASN lookups  

```bash
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

asnmap -a AS5650            # by ASN
asnmap -i 100.19.12.21      # by IP
asnmap -d google.com        # by domain
asnmap -org GOOGLE          # by org name
asnmap -a AS5650 -j         # JSON output
```

---

### tlsx
**GitHub**: https://github.com/projectdiscovery/tlsx  
**Purpose**: TLS probing — SANs, CN, JARM, JA3 fingerprints, expired/self-signed cert detection  

```bash
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

tlsx -u example.com           # basic TLS scan
tlsx -u example.com -san      # extract SANs
tlsx -u example.com -jarm     # JARM fingerprint
tlsx -u example.com -ja3      # JA3 fingerprint
tlsx -l hosts.txt -json       # batch + JSON
tlsx -u example.com -ex       # find expired certs
```

---

### theHarvester
**GitHub**: https://github.com/laramies/theHarvester  
**Purpose**: OSINT — emails, subdomains, names, IPs via search engines + threat intel APIs  
**Python**: >= 3.12  

```bash
# Install
git clone https://github.com/laramies/theHarvester /opt/theHarvester
pip3 install -r /opt/theHarvester/requirements/base.txt

# Usage
python3 theHarvester.py -d example.com -b all
python3 theHarvester.py -d example.com -b google,bing,crtsh -l 500
python3 theHarvester.py -d example.com -b shodan -f report.html
```

**API Keys** (`api-keys.yaml`): Shodan, Censys, SecurityTrails, VirusTotal, Hunter.io

---

### whois
**Purpose**: WHOIS protocol client for domain/IP/ASN lookups  

```bash
sudo apt install whois          # Linux
brew install whois              # macOS

whois example.com               # domain
whois 8.8.8.8                   # IP
whois AS15169                   # ASN
```

---

### dnsx
**GitHub**: https://github.com/projectdiscovery/dnsx  
**Purpose**: Fast DNS toolkit — resolve multiple record types, bulk resolution, wildcard filtering, brute-force  

```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

dnsx -l subdomains.txt -a -resp                      # resolve with response
dnsx -l subdomains.txt -a -aaaa -cname -resp         # multi record types
dnsx -d example.com -w wordlist.txt -r resolvers.txt # brute-force
dnsx -l domains.txt -recon -j -o results.json        # full recon JSON
```

---

### alterx
**GitHub**: https://github.com/projectdiscovery/alterx  
**Purpose**: DSL-powered subdomain permutation wordlist generator  

```bash
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

echo "api.example.com" | alterx                   # generate permutations
echo "api.example.com" | alterx | dnsx            # generate + resolve
alterx -l subdomains.txt -o wordlist.txt          # save wordlist
```

---

### cdncheck
**GitHub**: https://github.com/projectdiscovery/cdncheck  
**Purpose**: Detects CDN/WAF/Cloud providers (Cloudflare, AWS, Akamai, Fastly, etc.)  

```bash
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

cdncheck -i 104.16.123.96                          # single IP
cat targets.txt | cdncheck -cdn                    # filter CDN only
cdncheck -i targets.txt -match-waf cloudflare      # specific WAF
```

---

### shuffledns
**GitHub**: https://github.com/projectdiscovery/shuffledns  
**Purpose**: Wrapper around massdns for fast active subdomain brute-force with wildcard filtering  
**⚠️ REQUIRES massdns binary on PATH**  

```bash
# Step 1: Install massdns (REQUIRED FIRST)
git clone https://github.com/blechschmidt/massdns /opt/massdns
cd /opt/massdns && make -j$(nproc) && sudo cp bin/massdns /usr/local/bin/

# Step 2: Install shuffledns
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Usage
shuffledns -d example.com -w wordlist.txt -r resolvers.txt    # brute-force
shuffledns -d example.com -l subs.txt -r resolvers.txt -o out # resolve list
```

---

### httpx (ProjectDiscovery)
**GitHub**: https://github.com/projectdiscovery/httpx  
**Purpose**: Fast multi-probe HTTP toolkit — status, title, tech stack, TLS, CDN, JARM, favicon, screenshots  
**Go**: >= 1.25 | **⚠️ Name collision** with Python httpx CLI  

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify it's the right one:
httpx -version   # should say "ProjectDiscovery"

httpx -l targets.txt -sc -title -tech-detect             # probe with info
httpx -l targets.txt -cdn -ip -cname -json -o out.json   # full JSON
httpx -u https://example.com -screenshot -system-chrome  # screenshots (needs Chrome)
httpx -l targets.txt -follow-redirects                   # follow redirects
```

---

### whatweb
**GitHub**: https://github.com/urbanadventurer/WhatWeb  
**Purpose**: Web tech fingerprinting — 1,800+ plugins; CMS, frameworks, analytics, JS libs, servers  
**Runtime**: Ruby 2.x/3.x  

```bash
sudo apt install whatweb                               # Debian/Kali
brew install whatweb                                  # macOS

whatweb example.com                                   # basic
whatweb -i targets.txt -a 3 --log-json=out.json      # file input, aggressive, JSON
whatweb --search-plugins wordpress                    # plugin search
# Aggression: 1=stealthy, 3=aggressive, 4=very aggressive
```

---

### wafw00f
**GitHub**: https://github.com/EnableSecurity/wafw00f  
**Purpose**: WAF fingerprinting — detects 100+ WAF products  
**Python**: >= 3.10  

```bash
pip3 install wafw00f                    # pip
sudo apt install wafw00f               # Kali

wafw00f https://example.com             # detect WAF
wafw00f -l                             # list all supported WAFs
wafw00f -a https://example.com         # test all rules
wafw00f -i targets.txt                 # from file
```

---

### katana
**GitHub**: https://github.com/projectdiscovery/katana  
**Purpose**: Next-gen web crawler — standard HTTP + headless JS crawling  
**Go**: >= 1.25, CGO_ENABLED=1 | **Optional**: Chrome for headless mode  

```bash
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
# For headless: sudo apt install google-chrome-stable

katana -u https://example.com                          # basic crawl
katana -u https://example.com -hl -system-chrome       # headless JS
katana -list targets.txt -d 3 -jc -kf -j -o out.jsonl # deep crawl, JSON
```

---

### gau (getallurls)
**GitHub**: https://github.com/lc/gau  
**Purpose**: Passively fetches URLs from Wayback Machine, OTX, Common Crawl, URLScan  

```bash
go install github.com/lc/gau/v2/cmd/gau@latest

gau example.com                               # basic
cat domains.txt | gau --threads 5 -o urls.txt # multi-domain
gau --blacklist png,jpg,gif example.com        # exclude extensions
gau --fc 404,302 example.com                  # filter status codes
```

---

### waybackurls
**GitHub**: https://github.com/tomnomnom/waybackurls  
**Purpose**: Fetches all URLs known to Wayback Machine for a domain  

```bash
go install github.com/tomnomnom/waybackurls@latest

echo "example.com" | waybackurls > urls.txt   # single domain
cat domains.txt | waybackurls                 # multi-domain
echo "example.com" | waybackurls -no-subs     # no subdomains
```

---

### waymore
**GitHub**: https://github.com/xnl-h4ck3r/waymore  
**Purpose**: Extended URL discovery + archives **response body** downloader (Wayback + 6 more sources)  
**Python**: >= 3.7  

```bash
pip install waymore

waymore -i example.com -mode U -oU urls.txt           # URLs only
waymore -i example.com -mode B -oU urls.txt -oR ./r/  # URLs + responses
waymore -i example.com -mc 200,302                    # filter status codes
```

---

### arjun
**GitHub**: https://github.com/s0md3v/Arjun  
**Purpose**: HTTP parameter discovery — GET/POST/JSON/XML with 25,000+ word wordlist  

```bash
pipx install arjun
# or: pip install arjun

arjun -u https://api.example.com/v1/user        # GET params
arjun -u https://example.com/login -m POST      # POST params
arjun -i urls.txt -oJ params.json -t 10         # batch, JSON, 10 threads
```

---

### paramspider
**GitHub**: https://github.com/devanshbatham/ParamSpider  
**Purpose**: Mines parameter-bearing URLs from archives, injects FUZZ placeholder  

```bash
git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider
pip3 install -e /opt/paramspider/

paramspider -d example.com                       # single domain
paramspider -d example.com -s                    # stream to stdout
paramspider -l domains.txt                       # from file
# Pipeline:
paramspider -d example.com -s | ffuf -u FUZZ -w -
```

---

### ffuf
**GitHub**: https://github.com/ffuf/ffuf  
**Purpose**: High-speed web fuzzer — directories, vhosts, GET/POST params using FUZZ keyword  

```bash
go install github.com/ffuf/ffuf/v2@latest
# or: sudo apt install ffuf

ffuf -w wordlist.txt -u https://target/FUZZ                        # directory
ffuf -w vhosts.txt -u https://target -H "Host: FUZZ" -fs 4242     # vhost
ffuf -w params.txt -u https://target?FUZZ=test -fs 4242           # GET param
ffuf -w words.txt -X POST -d "pass=FUZZ" -u https://target/login  # POST
ffuf -w wordlist.txt -u https://target/FUZZ -mc 200,301,302       # match codes
ffuf -w wordlist.txt -u https://target/FUZZ -e .php,.html,.js     # extensions
ffuf -w wordlist.txt -u https://target/FUZZ -rate 100             # rate limit
```

---

### feroxbuster
**GitHub**: https://github.com/epi052/feroxbuster  
**Purpose**: Fast recursive forced browsing in Rust — auto-recurses into discovered directories  

```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
# or: sudo apt install feroxbuster

feroxbuster -u http://example.com -w wordlist.txt                 # basic
feroxbuster -u http://example.com -x php,html,js -w wordlist.txt # extensions
feroxbuster -u http://example.com --depth 3                      # depth limit
feroxbuster -u http://example.com --no-recursion                 # no recurse
cat targets.txt | feroxbuster --stdin -w wordlist.txt            # stdin
```

---

### jsluice
**GitHub**: https://github.com/BishopFox/jsluice  
**Purpose**: AST-based JS analysis (Tree-sitter) — extracts URLs, paths, API keys, secrets; resolves variable concatenation  

```bash
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

jsluice urls target.js                          # extract URLs
jsluice secrets target.js                      # extract secrets
jsluice urls -R https://example.com target.js  # resolve relative paths
curl -sL https://example.com/app.js | jsluice secrets  # from URL
```

---

### retire.js
**GitHub**: https://github.com/RetireJS/retire.js  
**Purpose**: Detects outdated/vulnerable JavaScript libraries; generates CycloneDX SBOM  
**Runtime**: Node.js >= 14  

```bash
npm install -g retire

retire                                              # scan current dir
retire --path ./src                                # specific path
retire --outputformat cyclonedx --outputpath sbom.json  # SBOM
retire --severity high                             # filter severity
```

---

### linkfinder
**GitHub**: https://github.com/GerbenJavado/LinkFinder  
**Purpose**: Regex-based JS endpoint extractor — URLs, relative paths, hidden parameters  

```bash
git clone https://github.com/GerbenJavado/LinkFinder /opt/linkfinder
pip3 install -r /opt/linkfinder/requirements.txt

python3 linkfinder.py -i https://example.com/app.js -o results.html
python3 linkfinder.py -i app.js -o cli              # stdout
python3 linkfinder.py -i https://example.com -d     # domain crawl
python3 linkfinder.py -i burp_file.xml -b           # Burp XML
```

---

### naabu
**GitHub**: https://github.com/projectdiscovery/naabu  
**Purpose**: High-speed TCP/UDP port scanner with SYN/CONNECT modes, CDN exclusion, Nmap integration  
**⚠️ REQUIRES libpcap-dev**  

```bash
sudo apt install libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

naabu -host hackerone.com                           # basic
naabu -host hackerone.com -p 80,443,8080            # specific ports
naabu -host hackerone.com -top-ports 1000           # top 1000 ports
naabu -l hosts.txt -p 80,443 -o results.txt         # from file
naabu -host target.com -sV                          # service detection
naabu -host target.com -nmap-cli 'nmap -sV'         # then run nmap
naabu -host target.com -exclude-cdn                 # skip CDN hosts
```

---

### nmap
**GitHub**: https://github.com/nmap/nmap  
**Purpose**: Gold standard network scanner — host discovery, port scan, OS fingerprinting, version detection, NSE scripts  
**License**: NPSL (check commercial use)  

```bash
sudo apt install nmap

nmap example.com                                    # basic TCP scan
nmap -sS -sV -O -p 1-1000 example.com             # comprehensive
nmap -A example.com                                 # aggressive
nmap -sU example.com                               # UDP scan
nmap --script=vuln example.com                     # vulnerability NSE
nmap -oA output_base example.com                   # all output formats
nmap -iL hosts.txt                                 # from file
```

**EasyHunt blocks NSE categories**: exploit, dos, brute, malware

---

### masscan
**GitHub**: https://github.com/robertdavidgraham/masscan  
**Purpose**: Internet-scale async TCP scanner — up to 10M packets/sec, custom TCP/IP stack  
**⚠️ REQUIRES root / CAP_NET_RAW**  

```bash
sudo apt install masscan
# or from source (latest):
git clone https://github.com/robertdavidgraham/masscan /opt/masscan
cd /opt/masscan && make -j$(nproc) && sudo make install

sudo masscan -p80,443 10.0.0.0/8 --rate 10000      # subnet scan
sudo masscan -p0-65535 10.0.0.0/8 --rate 50000     # all ports
sudo masscan -p80 10.0.0.0/8 --banners             # banner grabbing
```

---

### subzy
**GitHub**: https://github.com/PentestPad/subzy  
**Purpose**: Subdomain takeover checker — matches HTTP responses against fingerprint DB  

```bash
go install -v github.com/PentestPad/subzy@latest

subzy run --target sub.example.com                 # single target
subzy run --targets subdomains.txt                 # from file
subzy run --targets subs.txt --concurrency 20      # faster
subzy run --targets subs.txt --hide_fails          # only show vulnerable
```

---

### dnsreaper
**GitHub**: https://github.com/punk-security/dnsReaper  
**Purpose**: Cloud-aware DNS takeover scanner — fetches from AWS/Azure/GCP APIs; 50+ signatures  
**Python**: >= 3.9 | **⚠️ AGPL-3.0**  

```bash
# Method 1: Docker (recommended)
docker pull punksecurity/dnsreaper:latest
docker run -it --rm punksecurity/dnsreaper file --filename subs.txt

# Method 2: Python
git clone https://github.com/punk-security/dnsReaper /opt/dnsreaper
cd /opt/dnsreaper && pip3 install -r requirements.txt

python main.py single --domain example.com
python main.py file --filename subdomains.txt
python main.py aws --aws-access-key-id KEY --aws-access-key-secret SECRET
python main.py file --filename subs.txt --pipeline   # CI/CD exit code
```

---

### dig
**Purpose**: DNS lookup tool — CNAME chain resolution; essential for takeover verification  

```bash
sudo apt install dnsutils      # provides dig

dig example.com                # A record
dig example.com CNAME          # CNAME chain
dig @8.8.8.8 example.com A    # use specific resolver
dig +trace example.com         # full delegation trace
```

---

### kingfisher
**GitHub**: https://github.com/mongodb/kingfisher  
**Purpose**: SIMD-accelerated secret scanner + live credential validation; HTML report; revocation support  

```bash
brew install kingfisher
# or: pip install kingfisher-bin
# or: curl -sSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | bash

kingfisher scan /path/to/code                      # scan directory
kingfisher scan /path/to/code --view-report        # scan + HTML report
kingfisher scan /path/to/code --only-valid         # only live credentials
kingfisher scan /path/to/code --access-map         # cloud blast radius
kingfisher scan /path/to/code --redact             # mask secrets in output
kingfisher revoke --rule github "ghp_xxxx..."      # revoke found token
```

---

### noseyparker
**GitHub**: https://github.com/praetorian-inc/noseyparker  
**Purpose**: Rust secret scanner — 188 regex rules, deduplication, git history, GitHub orgs  
**⚠️ Status**: Officially retired (successor: Titus by Praetorian)  

```bash
brew install noseyparker
# or Docker: docker pull ghcr.io/praetorian-inc/noseyparker:latest

noseyparker scan --datastore ./np_db /path/to/target
noseyparker scan --datastore ./np_db --github-org ORG
noseyparker report --datastore ./np_db --format json
```

---

### trufflehog
**GitHub**: https://github.com/trufflesecurity/trufflehog  
**Purpose**: Secret discovery + live validation — 800+ secret types across git, S3, Docker, Postman  
**⚠️ AGPL-3.0**  

```bash
brew install trufflehog
# or: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

trufflehog git https://github.com/org/repo --results=verified
trufflehog filesystem /path/to/target
trufflehog github --org=myorg --results=verified
trufflehog s3 --bucket=my-bucket --results=verified,unknown
trufflehog docker --image=ubuntu:latest
trufflehog git https://github.com/org/repo --json
```

---

### gitleaks
**GitHub**: https://github.com/gitleaks/gitleaks  
**Purpose**: Lightweight SAST secret scanner — Git repos, directories, stdin; pre-commit hooks  

```bash
go install github.com/gitleaks/gitleaks/v8@latest
# or: brew install gitleaks

gitleaks git -v /path/to/repo                     # git repo
gitleaks dir -v /path/to/directory                # directory
cat file.txt | gitleaks stdin -v                  # stdin
gitleaks git --report-path report.json --report-format json
```

---

### cloud_enum
**GitHub**: https://github.com/initstring/cloud_enum  
**Purpose**: Multi-cloud OSINT — AWS S3/awsapps, Azure storage/databases/VMs, GCP buckets/Firebase  

```bash
git clone https://github.com/initstring/cloud_enum /opt/cloud_enum
pip3 install -r /opt/cloud_enum/requirements.txt

python3 cloud_enum.py -k targetcompany             # basic
python3 cloud_enum.py -k targetcompany -m mutations.txt
python3 cloud_enum.py -k targetcompany --disable-aws
python3 cloud_enum.py -k target1 -k target2       # multiple keywords
```

---

### s3scanner
**GitHub**: https://github.com/sa7mon/S3Scanner  
**Purpose**: S3 bucket misconfiguration scanner — AWS, GCP, DigitalOcean, Linode, Scaleway  

```bash
go install -v github.com/sa7mon/s3scanner@latest

s3scanner -bucket my-target-bucket                 # single
s3scanner -bucket-file names.txt -enumerate        # from file + enumerate contents
s3scanner -provider gcp -bucket my-bucket          # GCP
s3scanner -bucket-file names.txt -json             # JSON
```

---

### cloudfox
**GitHub**: https://github.com/BishopFox/cloudfox  
**Purpose**: Cloud attack path discovery for AWS/Azure/GCP  
**Auth Deps**: AWS SecurityAudit IAM policy; gcloud auth; Azure credentials  

```bash
go install github.com/BishopFox/cloudfox@latest
# or: brew install cloudfox

cloudfox aws --profile NAME all-checks             # all AWS checks
cloudfox aws -a all-checks                         # all configured profiles
cloudfox gcp --project PROJECT_ID all-checks       # GCP
cloudfox azure --subscription SUB_ID all-checks    # Azure
```

---

### prowler
**GitHub**: https://github.com/prowler-cloud/prowler  
**Purpose**: CSPM platform — AWS/Azure/GCP/K8s/M365 vs CIS/NIST/PCI-DSS/SOC2/GDPR  
**Python**: >= 3.9  

```bash
pip install prowler
# or: brew install prowler
# or: docker run --rm -it ghcr.io/prowler-cloud/prowler:latest aws

prowler aws                                        # AWS assessment
prowler azure --sp-env                             # Azure
prowler gcp                                        # GCP
prowler k8s                                        # Kubernetes
prowler aws --compliance cis_1.5_aws               # specific benchmark
prowler aws -M json sarif csv                      # multiple output formats
prowler dashboard                                  # local web dashboard
```

---

### kubescape
**GitHub**: https://github.com/kubescape/kubescape  
**Purpose**: Kubernetes security — NSA-CISA/MITRE/CIS scanning, image vuln scan, eBPF runtime monitoring  

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
# or: brew install kubescape
# or: kubectl krew install kubescape

kubescape scan                                     # scan running cluster
kubescape scan /path/to/manifests/                 # scan YAML files
kubescape scan image nginx:latest                  # scan container image
kubescape scan framework nsa                       # NSA-CISA framework
kubescape scan --format json --output results.json
```

---

### dalfox
**GitHub**: https://github.com/hahwul/dalfox  
**Purpose**: XSS scanner and parameter analyzer. v3=Rust, v2=Go. AST verification, WAF bypass analysis  

```bash
# v3 Rust (current)
cargo install dalfox
# v2 Go (stable)
go install github.com/hahwul/dalfox/v2@latest
# or: brew install dalfox

dalfox url "http://target/?cat=1"           # single URL
dalfox file urls.txt                        # from file
cat urls.txt | dalfox pipe                  # stdin
dalfox url "http://target/?id=1" --only-poc # show PoC only
dalfox url "http://target/?id=1" --silence  # quiet mode
```

---

### sqlmap
**GitHub**: https://github.com/sqlmapproject/sqlmap  
**Purpose**: SQL injection detection. In EasyHunt: detection ONLY — extraction flags hard-blocked  
**⚠️ EasyHunt hard-blocks**: --dump, --dbs, --tables, --os-shell, --file-read, --tamper, --proxy  

```bash
pip install sqlmap
# or: sudo apt install sqlmap
# or: git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git

sqlmap -u "http://target/?id=1" --batch            # detection, no interaction
sqlmap -u "http://target/?id=1" --batch --level 3 --risk 2
sqlmap -r request.txt --batch                      # from saved HTTP request
sqlmap -u "http://target/?id=1" --batch --technique BEUSTQ
```

---

### interactsh-client
**GitHub**: https://github.com/projectdiscovery/interactsh  
**Purpose**: OOB interaction detection — DNS/HTTP/SMTP/LDAP/NTLM callbacks. Proves SSRF, blind injection, XXE  

```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

interactsh-client                                  # default (public server)
interactsh-client -server hackwithautomation.com   # self-hosted
interactsh-client -token SECRET_TOKEN              # authenticated
interactsh-client -n 5                             # 5 payloads
interactsh-client -json -sf session.file           # JSON + persist session
```

---

### garak
**GitHub**: https://github.com/NVIDIA/garak  
**Purpose**: NVIDIA LLM vulnerability scanner — jailbreaks, prompt injection, data leakage, toxicity  
**Python**: >= 3.10, <= 3.12  

```bash
pip install -U garak
# or Docker: docker run -it nvcr.io/nvidia/garak:latest

python -m garak --target_type openai --target_name gpt-4o --probes encoding
python -m garak --target_type huggingface --target_name gpt2 --probes dan.Dan_11_0
python -m garak --list_probes
```

**Env vars**: OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.

---

### promptfoo
**GitHub**: https://github.com/promptfoo/promptfoo  
**Purpose**: LLM evaluation and red-teaming — safety, jailbreaks, prompt injection, PII, web dashboard  
**Runtime**: Node.js >= 20  

```bash
npm install -g promptfoo
# or: npx promptfoo@latest

promptfoo init                                     # initialize
promptfoo eval                                     # run evaluations
promptfoo redteam run                              # red-team scan
promptfoo view                                     # web dashboard
```

---

### deepteam
**GitHub**: https://github.com/confident-ai/deepteam  
**Purpose**: LLM red-teaming — jailbreaks, prompt injection, PII leakage, BFLA, BOLA against AI agents/RAG  
**Python**: >= 3.9  

```bash
pip install deepteam

deepteam test                  # run red-team tests
deepteam login                 # Confident AI platform auth
```

---

### bbot
**GitHub**: https://github.com/blacklanternsecurity/bbot  
**Purpose**: OSINT/recon/ASM framework — 80+ modules, event-driven, subdomain enum, spidering, port scan, email harvest  
**Python**: >= 3.10 | **⚠️ AGPL-3.0**  

```bash
pipx install bbot              # recommended
# or: pip install bbot

bbot -t evilcorp.com -p subdomain-enum   # subdomain enumeration
bbot -t evilcorp.com -p spider           # web spider
bbot -t evilcorp.com -p email-enum       # email enumeration
bbot -t evilcorp.com -p web              # quick web scan
bbot -t evilcorp.com -p web-thorough     # thorough web scan
bbot -t evilcorp.com -rf passive         # passive only
```

**Presets**: subdomain-enum, cloud-enum, code-enum, email-enum, web-basic, web-thorough, spider, paramminer, baddns

---

### nuclei
**GitHub**: https://github.com/projectdiscovery/nuclei  
**Purpose**: Template-based vulnerability scanner — YAML templates for HTTP/DNS/TCP/WHOIS/SSL/Code/JS  
**⚠️ EasyHunt blocks tags**: dos, fuzz, intrusive, bruteforce  

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or: brew install nuclei

nuclei -u https://example.com                     # single target
nuclei -l targets.txt                             # from file
nuclei -u https://example.com -s critical,high    # by severity
nuclei -u https://example.com -tags cve,xss       # by tags
nuclei -u https://example.com -as                 # auto-detect tech
nuclei -u https://example.com -j -o out.jsonl     # JSON output
nuclei -update-templates                          # update template library
```

---

### semgrep
**GitHub**: https://github.com/semgrep/semgrep  
**Purpose**: Fast SAST — 30+ languages, IaC, JS bundles; write rules in source syntax; runs offline  

```bash
pip install semgrep
# or: brew install semgrep

semgrep scan --config auto                        # auto rules
semgrep scan --config p/security-audit            # security audit
semgrep scan --metrics=off --config auto .        # offline mode
semgrep scan --json --output results.json
semgrep scan --sarif --output results.sarif       # SARIF for GitHub
```

---

### jaeles
**GitHub**: https://github.com/jaeles-project/jaeles  
**Purpose**: YAML request/response signature scanner. Only `rules/jaeles/` directory is scanned  
**⚠️ Status**: Repository archived — no longer maintained  

```bash
go install github.com/jaeles-project/jaeles@latest
git clone https://github.com/jaeles-project/jaeles-signatures /opt/jaeles-signatures

jaeles scan -s /opt/jaeles-signatures/cves/ -u http://example.com
jaeles scan -s /opt/jaeles-signatures/ -U list.txt -c 50
```

---

### osmedeus
**GitHub**: https://github.com/j3ssie/osmedeus  
**Purpose**: Declarative security orchestration — YAML Modules + Flows; Redis distributed clusters  

```bash
curl -sSL http://www.osmedeus.org/install.sh | bash

osmedeus run -m recon -t example.com    # recon module
osmedeus run -f general -t example.com  # general flow
osmedeus run -f cidr -t 10.0.0.0/8    # CIDR targets
osmedeus server --master               # master node
osmedeus worker --slave                # worker node
```

---

## Critical Notes for Auto-Installation

### Tools Needing Root / Elevated Permissions
```bash
# Run as root or with sudo
naabu    # SYN scan needs raw sockets
nmap     # SYN scan -sS needs raw sockets
masscan  # always needs raw sockets
```

### External Hard Dependencies (install BEFORE the tool)
| Tool | Dependency | Install |
|------|-----------|---------|
| naabu | libpcap | `sudo apt install libpcap-dev` |
| nmap | libpcap | `sudo apt install libpcap-dev` |
| masscan | libpcap | `sudo apt install libpcap-dev` |
| shuffledns | massdns binary | see Group F above |
| katana (headless) | Google Chrome | `sudo apt install google-chrome-stable` |
| httpx (screenshot) | Google Chrome | `sudo apt install google-chrome-stable` |
| findomain (screenshot) | Google Chrome | `sudo apt install google-chrome-stable` |

### PATH Collision Warning
```bash
# After go install httpx, verify the right binary:
httpx -version   # must say "ProjectDiscovery"
# If Python httpx shadows it, remove it:
pip uninstall httpx-cli
```

### Archived / Deprecated Tools
| Tool | Status | Alternative |
|------|--------|------------|
| noseyparker | Officially retired | Titus (Praetorian) or trufflehog |
| jaeles | Repository archived | Still works, no security updates |

### AGPL-3.0 Tools (review before commercial use)
- bbot, trufflehog, dnsreaper, masscan

---

## API keys

Provider keys (subfinder, theHarvester, amass), cloud credentials and the
LLM key are documented once, in
[`USERMANUAL.md` section 4](USERMANUAL.md#4-configuration-files) — they are
configuration, not tool reference, and a second copy here drifted from the
first. None are required; they widen the sources recon can reach.
