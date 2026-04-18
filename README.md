 # DEV NOTE: I found like 600 bugs in the bash script and it's honestly so broken. Instead of debugging every single line of an already overbloated bash script. I'm just going forward with the Go rebase. With a SLEW of new features! It's going to be a complete re-write, restructure, and upgrade from V1. So stay tuned!
 # Foxhunt v1.0.0
The Interactive Orchestration Layer for Modern Bug Bounty Recon.

Foxhunt is a sophisticated Bash-based reconnaissance framework designed to bridge the gap between manual one-liners and heavy, inflexible automation suites. It provides a custom interactive shell environment to manage programs, targets, and scope with persistent state.


## Core Features
**Custom Interactive Shell:** A dedicated CLI environment with context-aware prompts (Program/Target tracking).

**24-Stage Tactical Pipeline:** A comprehensive recon flow covering passive/active discovery, DNS resolution, VHost fuzzing, JS analysis, and vulnerability scanning.

**Smart Skip Logic:** Custom SIGINT handling allows you to skip a specific tool/stage (Ctrl+C) without killing the entire session.

**Persistent Configuration:** Automatically saves and loads program-specific settings and global user defaults.

**Obsidian Integration:** Generates a structured .md summary at the end of every run, ready for your knowledge base.

**Modular Design:** Easily toggle "Quick Mode" or "Exploit Mode" depending on your engagement depth.

## Config Options
Foxhunt includes many configurable options, allowing you to customize your methodology per-program or overall.

Foxhunt's global config is located at `~/.recon_config`    

session file is at `"~/.Foxhunt_session"`  

program config file is at `~/Projects/Bounties/[program]`  

Directories are all configurable in Foxhunt.sh



## Commands

Foxhunt v1.0.0 -- bug bounty recon shell

```plaintext
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
  exit / quit                     leave Foxhunt

No-program mode:
  set target example.com
  run
  Output goes to: ~/Projects/Bounties/no-program/<target>
```




## The Pipeline
Foxhunt orchestrates industry-standard tools into a unified stream:

**Passive Discovery:** subfinder, assetfinder, github-subdomains, amass.

**Resolution & Filtering:** shuffledns, httpx.

**Intelligence Gathering:** shodan, asn-enum.

**Endpoint Analysis:** katana, waybackurls, linkfinder.

**Vulnerability Probing:** nuclei, corsy, dalfox.

**Summary:** Automated stats and Obsidian-linked notes.



# Installation
## Clone the repository
`git clone https://github.com/mf-pro-repo/Foxhunt.git`
`cd Foxhunt`





## Run Foxhunt

First, run:

`chmod +x Foxhunt.sh && CONF_FILE=$([[ "$SHELL" =~ "zsh" ]] && echo "$HOME/.zshrc" || echo "$HOME/.bashrc"); echo "alias Foxhunt='$(readlink -f Foxhunt.sh)'" >> "$CONF_FILE" && source "$CONF_FILE"`


Then it'll just respond to Foxhunt

Usage:

`$> Foxhunt`

![WindowsTerminal_WvDp7Frb5V](https://github.com/user-attachments/assets/8f839782-35da-4ee2-8e52-fb94af5033b0)

Please note in the above example, I hadn't set the alias.


Once inside the Foxhunt shell, use the following workflow:
Please ensure all dependencies are installed/configured, it'll run without them, but it defeats the purpose

This can be verified with `Foxhunt > check`

```Plaintext
[Foxhunt]> set program ExampleCorp
[Foxhunt:ExampleCorp]> set scope [scope.txt]  ## Right now this must be manually created, a simple .txt file with one in-scope target per line works or just type in the domain and it'll be added to scope.
[Foxhunt:ExampleCorp]> verify scope
[Foxhunt:ExampleCorp]> set target [api.example.com]
[Foxhunt:ExampleCorp:api.example.com]> run
```

Commands
`set program <name>`: Switch engagement context.

`set target <domain>`: Set the active scan target.

`set scope <file/list>`: Define authorized boundaries.

`show`: Display current configuration and API key status.

`run`: Execute the 24-stage pipeline.



## Notes:

Please verify your program's rules of engagement regarding scope, rate limits, custom headers, and automated scanning tools (nmap, nuclei) before running.



## Dependencies:
```plaintext
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
  asnmap  ***REQUIRES API KEY SET IN GLOBAL CONFIG AND INITIALIZED VIA CLI**
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

**Recomended**
  Obsidian - Integrated for ease of navigation through the vault, all outputs are formated in markdown for vault access, and txt (in /data) QoL)
```
## Why?
Because I hated juggling a ton of tools, piping output, making random txt files with "interesting_JS_XXXXX" or whatever. I built this tool for my workflow and it fits in perfectly for me. It keeps me from forgetting which header to use, what scope I'm working in, and it makes my notes actually make sense instead of "JS bundle at example.com.js contains interesting endpoints." I get the endpoints in a fancy little list.

Plus I like scripting.

### Why "Foxhunt"

Foxes are adorable.

## Support, Issues, & Feedback
I'm open to any and all questions, comments, concerns, bitches, moans, and gripes. I put this out here because I think it's cool and I'm proud of it. 

* **Logic is trash?** Tell me how to fix it.
* **Feature request?** Drop it in the issues tab.
* **Something broke?** I'll read every single one and see what I can do.

Please keep in mind: I am one guy, probably scripting in bed at 3am. I'm not a master dev, so don't expect this tool to ever be perfect.

### Troubleshooting "Zero Results"
If some of your stages come up empty, read this before yelling at me.
1. **Check the Basics:** Verify your DNS, check for a WAF, and run a manual `curl`.
2. **Understand the Tooling:** Some tools (like Nuclei) are very precise. Most security teams run these same tools, if the "low hanging fruit" is already patched, you won't see an output. That's totally normal.
3. **Check API:** Some of these tools require an API set in global config. If you don't have them, nothing will show up.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer
This tool is intended for legal bug bounty programs and authorized pentesting only. The user is responsible for ensuring compliance with the program's Rules of Engagement. Use with caution active scanning can be resource-intensive, dont do bad stuff.
