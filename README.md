🦊 
# FoxHunt v5.0
The Interactive Orchestration Layer for Modern Bug Bounty Recon.

FoxHunt is a sophisticated Bash-based reconnaissance framework designed to bridge the gap between manual one-liners and heavy, inflexible automation suites. It provides a custom interactive shell environment to manage programs, targets, and scope with persistent state.

## Core Features
Custom Interactive Shell: A dedicated CLI environment with context-aware prompts (Program/Target tracking).

24-Stage Tactical Pipeline: A comprehensive recon flow covering passive/active discovery, DNS resolution, VHost fuzzing, JS analysis, and vulnerability scanning.

Smart Skip Logic: Custom SIGINT handling allows you to skip a specific tool/stage (Ctrl+C) without killing the entire session.

Persistent Configuration: Automatically saves and loads program-specific settings and global user defaults.

Obsidian Integration: Generates a structured .md summary at the end of every run, ready for your knowledge base.

Modular Design: Easily toggle "Quick Mode" or "Exploit Mode" depending on your engagement depth.

## Config Options
Foxhunt includes many configurable options, allowing you to customize your methodology per-program or overall.

foxhunt's global config is located at `~/.recon_config`
session file is at `"~/.foxhunt_session"`
program config file is at `~/Projects/Bounties/[program]`

Directories are all configurable in foxhunt.sh

## Commands

FOXHUNT v5.0 -- bug bounty recon shell

Workflow:
  set program <name>              create/open a program
  set scope <domains|file>        set scope (CSV, newline, or .txt file)
  verify scope                    list current scope
  set target <domain>             set target (warns if out of scope)
  run                             run pipeline (resumes from checkpoint)
  run fresh                       run pipeline from scratch

Config (saved per-program):
  set mode <full|quick>           scan depth (default: full)
  set proxy <true|false>          route through proxy
  set proxy-port <port>           proxy port (default: 8080)
  set exploit <true|false>        enable XSS stage
  set portscan <true|false>       port scan (default: false, check scope)
  set nuclei <true|false>         run nuclei (default: true)
  set nuclei-timeout <sec>        hard cap (default: 300, 0=none)
  set httpx-timeout <sec>         per-request timeout (default: 10)
  set asnmap-timeout <sec>        asnmap cap (default: 90, 0=none)
  set notify <true|false>         desktop notification on complete
  set rate <n>                    req/sec (default: 50)
  set threads <n>                 thread count (default: 10)
  set dns <ip>                    resolver (default: 8.8.8.8)
  set ua <string>                 user agent
  set header "Key: Value"         add custom header (stacks)
  unset header "Key: Value"       remove a header
  unset headers                   clear all headers
  unset scope                     clear scope
  unset target                    clear active target
  unset program                   leave program, enter no-program mode

Info:
  show                            current session state
  programs                        list all programs
  check                           verify toolchain
  help                            this screen
  exit / quit                     leave foxhunt

No-program mode:
  set target example.com
  run
  Output goes to: ~/Projects/Bounties/no-program/<target>


## The Pipeline
FoxHunt orchestrates industry-standard tools into a unified stream:

Passive Discovery: subfinder, assetfinder, github-subdomains, amass.

Resolution & Filtering: shuffledns, httpx.

Intelligence Gathering: shodan, asn-enum.

Endpoint Analysis: katana, waybackurls, linkfinder.

Vulnerability Probing: nuclei, corsy, dalfox.

Summary: Automated stats and Obsidian-linked notes.

## Installation
Bash
# Clone the repository
`git clone https://github.com/mf-pro-repo/BugBounty-Writeups.git`
`cd BugBounty-Writeups`

# Run FoxHunt

First, run:

`chmod +x foxhunt.sh && CONF_FILE=$([[ "$SHELL" =~ "zsh" ]] && echo "$HOME/.zshrc" || echo "$HOME/.bashrc"); echo "alias foxhunt='$(readlink -f foxhunt.sh)'" >> "$CONF_FILE" && source "$CONF_FILE"`


Then it'll just respond to foxhunt

Usage:

`$> foxhunt`

Once inside the FoxHunt shell, use the following workflow:
Please ensure all dependancies are installed/configured, it'll run without them, but it defeats the purpose

This can be verified with `foxhunt > check`

```Plaintext
[foxhunt]> set program ExampleCorp
[foxhunt:ExampleCorp]> set scope [scope.txt]  ## Right now this must be manually created, a simple .txt file with one in-scope target per line works or just type in the domain and it'll be added to scope.
[foxhunt:ExampleCorp]> verify scope
[foxhunt:ExampleCorp]> set target [api.example.com]
[foxhunt:ExampleCorp:api.example.com]> run
```

Commands
`set program <name>`: Switch engagement context.

`set target <domain>`: Set the active scan target.

`set scope <file/list>`: Define authorized boundaries.

`show`: Display current configuration and API key status.

`run`: Execute the 24-stage pipeline.



## Notes:

Please make sure you verify your programs guidelines as it pertains to scope, rate limit, headers, and 

automated scanning (nmap, nuclei)



## Dependancies:

**Enumeration**
subfinder  
amass  
assetfinder  
github-subdomains  ***REQUIRES API KEY SET IN GLOBAL CONFIG***

**DNS**
puredns  
massdns  
dnsx  
dig  

**Network Mapping**
asnmap  ***REQUIRES API KEY SET IN GLOBAL CONFIG AND INITIALIZED VIA CLIE***
nmap  

**Passive Intel**
Shodan - ***REQUIRES API KEY SET IN GLOBAL CONFIG AND INITIALIZED VIA CLI.***

**HTTP Probing**
httpx-toolkit
ffuf
gowitness
byp4xx

**URL and Parameter Discovery**
gau
katana
uro
paramspider
x8

**JS Analysis**
getJS
linkfinder.py

**Secrets and Scanning**
trufflehog
nuclei
s3scanner
cloud_enum.py
corsy.py

**Exploit**
dalfox

**Wordlists**
DNS bruteforce
Directories / x8

**VHOST Fuzzing**
seclists



## License
This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer
This tool is intended for legal bug bounty programs and authorized pentesting only. The user is responsible for ensuring compliance with the program's Rules of Engagement. Use with caution active scanning can be resource-intensive, dont do bad stuff.