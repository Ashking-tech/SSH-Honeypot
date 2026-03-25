# SSH Honeypot 2.0

A production-grade SSH honeypot designed to capture, analyze, and visualize attacker behavior. Built with Go, this honeypot emulates a realistic Ubuntu shell environment while logging every interaction for security research and threat intelligence.

![SSH Honeypot Dashboard](screenshot.png)

## Features

- **Realistic Shell Emulation** - Full pseudo-terminal with convincing Ubuntu 22.04 responses
- **Credential Harvesting** - Captures usernames, passwords, and geo-location data from every connection
- **Command Logging** - Records every command typed by attackers
- **Geo-IP Enrichment** - Automatically enriches logs with country, city, ISP, and coordinates
- **Rate Limiting** - Built-in protection against DoS attempts
- **REST API** - Real-time attack data via built-in HTTP server
- **Docker Ready** - One-command deployment anywhere

## Quick Start

```bash
# Run directly
go run .

# Or build and run with Docker
docker build -t ssh-honeypot .
docker run -p 2222:2222 -v $(pwd)/keys:/app/keys:z --restart always ssh-honeypot
```

Connect with any SSH client:

```bash
ssh root@localhost -p 2222
# Enter any password - they're all "accepted"
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Attacker      │────▶│  SSH Server      │────▶│  Fake Shell     │
│   (Port 2222)   │     │  (Go + crypto)   │     │  Emulation      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │                         │
                               ▼                         ▼
                        ┌──────────────┐         ┌──────────────┐
                        │ attacks.json │         │ honeypot.log │
                        │ (JSON Logs)  │         │ (Text Logs)  │
                        └──────────────┘         └──────────────┘
```

## Emulated Commands

| Category | Commands |
|----------|----------|
| **System Info** | `whoami`, `id`, `uname`, `hostname`, `uptime`, `date` |
| **File Operations** | `ls`, `ls -la`, `ls -l`, `ls -1`, `pwd`, `cat`, `cd`, `echo` |
| **Network** | `curl`, `wget` (simulated downloads) |
| **Utilities** | `env`, `printenv`, `history`, `clear`, `exit` |

The honeypot also responds to `cat` for fake files like `/etc/passwd`, `/etc/hosts`, `/proc/version`.

## Log Output

**Structured JSON** (`attacks.json`):
```json
{
  "time": "2026-03-21T14:23:45Z",
  "IP": "185.234.219.47",
  "user": "root",
  "password": "admin123",
  "country": "China",
  "city": "Beijing",
  "ISP": "China Telecom",
  "lat": 39.9042,
  "lon": 116.4074
}
```

**Plain Text** (`honeypot.log`):
```
2026/03/21 14:23:45 login attempt - ip: 185.234.x.x user: root password: admin123
2026/03/21 14:23:47 command received: uname -a
```

## Analysis Commands

```bash
# Top passwords tried
jq -r '.password' attacks.json | sort | uniq -c | sort -rn | head -10

# Top usernames attempted
jq -r '.user' attacks.json | sort | uniq -c | sort -rn | head -10

# Attack origins by country
jq -r '.country' attacks.json | sort | uniq -c | sort -rn

# Unique attacker IPs
jq -r '.IP' attacks.json | sort -u | wc -l
```

## Production Deployment

Deploy on a dedicated VM with port 22 exposed:

```bash
# Move real SSH to another port first
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Run honeypot on port 22
docker run -d -p 22:2222 -v $(pwd)/keys:/app/keys:z --user=0:0 --restart always ssh-honeypot
```

> **Warning**: Only deploy on isolated infrastructure you own. Never on machines with sensitive data.

## Tech Stack

- **Go** - High-performance SSH server implementation
- **golang.org/x/crypto/ssh** - SSH protocol
- **ED25519** - Secure host key generation
- **ip-api.com** - Free geo-IP lookup
- **Docker** - Containerized deployment

## What You'll Learn

Deploying this honeypot reveals:
- How bots systematically attempt default credentials
- Common attack patterns and payloads
- Global distribution of SSH attackers
- Why password authentication is dangerous

## Legal Notice

For educational and defensive security research only. Deploy only on infrastructure you own or have explicit permission to monitor.
