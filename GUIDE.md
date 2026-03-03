# SSH Honeypot in Go - Complete Guide

## Overview

An SSH honeypot is a security mechanism that mimics a real SSH server to attract attackers, log activity, and gather intelligence on attack patterns.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  SSH Server (TCP Listener on port 2222)                 │
│    │                                                    │
│    ▼                                                    │
│  SSH Handshake (golang.org/x/crypto/ssh)                │
│    │                                                    │
│    ▼                                                    │
│  Authentication Handler (log username/password)         │
│    │                                                    │
│    ▼                                                    │
│  Session Handler (fake shell, command logging)          │
│    │                                                    │
│    ▼                                                    │
│  Fake Filesystem (simulated responses)                  │
└─────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Implementation

### Step 1: Initialize the Project

```bash
cd "/home/ashking/Projects/SSH honeypot"
go mod init ssh-honeypot
```

---

### Step 2: Add the SSH Library

```bash
go get golang.org/x/crypto/ssh
```

---

### Step 3: Create the Basic Structure

Create `main.go` with this skeleton:

```go
package main

import (
    "fmt"
    "log"
    "net"
    "golang.org/x/crypto/ssh"
)

func main() {
    // 1. Load or generate host key
    // 2. Configure SSH server
    // 3. Listen on TCP port
    // 4. Accept connections and handle SSH handshake
}
```

---

### Step 4: Generate a Host Key

SSH requires a host key. You can either:

**Option A: Generate with ssh-keygen**
```bash
ssh-keygen -t ed25519 -f honeypot_key
```

**Option B: Generate programmatically**
```go
signer, err := ssh.GenerateKey(ssh.KeyAlgoED25519)
```

---

### Step 5: Configure SSH Server

```go
config := &ssh.ServerConfig{
    PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
        // LOG: username = conn.User(), password = string(password)
        // Return nil, nil to accept (keep attacker engaged)
        return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
    },
}
config.AddHostKey(yourPrivateKey)
```

---

### Step 6: Accept Connections

```go
listener, err := net.Listen("tcp", "0.0.0.0:2222")
if err != nil {
    log.Fatalf("Failed to listen: %v", err)
}
defer listener.Close()

log.Printf("SSH Honeypot listening on %s", listener.Addr())

for {
    conn, err := listener.Accept()
    if err != nil {
        log.Printf("Failed to accept connection: %v", err)
        continue
    }
    go handleConn(conn, config)
}
```

---

### Step 7: Handle SSH Handshake

```go
func handleConn(conn net.Conn, config *ssh.ServerConfig) {
    defer conn.Close()
    
    sshConn, channels, requests, err := ssh.NewServerConn(conn, config)
    if err != nil {
        log.Printf("Failed SSH handshake: %v", err)
        return
    }
    
    log.Printf("New connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
    
    // Handle channels (sessions)
    for newChan := range channels {
        go handleSession(newChan, sshConn)
    }
}
```

---

### Step 8: Handle Sessions (Shell Access)

```go
func handleSession(newChan ssh.NewChannel, sshConn *ssh.ServerConn) {
    channel, _, err := newChan.Accept()
    if err != nil {
        log.Printf("Failed to accept channel: %v", err)
        return
    }
    defer channel.Close()
    
    // Send welcome message
    welcomeMsg := "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
    channel.Write([]byte(welcomeMsg))
    
    // Show prompt
    username := sshConn.User()
    prompt := fmt.Sprintf("%s@honeypot:~$ ", username)
    channel.Write([]byte(prompt))
    
    // Read commands from attacker
    buf := make([]byte, 1024)
    for {
        n, err := channel.Read(buf)
        if err != nil {
            break
        }
        
        command := string(buf[:n])
        
        // LOG the command
        log.Printf("[%s] %s executed: %s", sshConn.RemoteAddr(), username, command)
        
        // Send fake response
        response := getFakeResponse(command)
        channel.Write([]byte(response))
        
        // Show prompt again
        channel.Write([]byte(prompt))
    }
}
```

---

### Step 9: Create Fake Command Responses

```go
func getFakeResponse(cmd string) string {
    // Trim whitespace and newlines
    cmd = strings.TrimSpace(cmd)
    
    // Parse command and arguments
    args := strings.Fields(cmd)
    if len(args) == 0 {
        return ""
    }
    
    switch args[0] {
    case "ls":
        return "file1.txt  file2.txt  documents  downloads\n"
    
    case "pwd":
        return "/home/" + os.Getenv("USER") + "\n"
    
    case "whoami":
        return "root\n"
    
    case "id":
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    
    case "uname":
        if len(args) > 1 && args[1] == "-a" {
            return "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
        }
        return "Linux\n"
    
    case "cat":
        if len(args) < 2 {
            return "cat: missing operand\nTry 'cat --help' for more information.\n"
        }
        return handleCat(args[1])
    
    case "cd":
        return "" // Silent success
    
    case "echo":
        if len(args) > 1 {
            return strings.Join(args[1:], " ") + "\n"
        }
        return "\n"
    
    case "exit":
        return ""
    
    case "wget", "curl":
        // Log download attempts
        log.Printf("Download attempt: %s", cmd)
        return ""
    
    default:
        return fmt.Sprintf("%s: command not found\n", args[0])
    }
}

func handleCat(filename string) string {
    switch filename {
    case "/etc/passwd":
        return "root:x:0:0:root:/root:/bin/bash\n" +
               "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
               "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    
    case "/etc/hosts":
        return "127.0.0.1\tlocalhost\n127.0.1.1\thonetypot\n"
    
    default:
        return fmt.Sprintf("cat: %s: No such file or directory\n", filename)
    }
}
```

---

### Step 10: Logging

Create a logger to track activity:

```go
type SessionLogger struct {
    logDir string
}

func NewSessionLogger(logDir string) (*SessionLogger, error) {
    if err := os.MkdirAll(logDir, 0755); err != nil {
        return nil, err
    }
    return &SessionLogger{logDir: logDir}, nil
}

func (sl *SessionLogger) LogAuth(remoteAddr, username, password string, success bool) {
    filename := filepath.Join(sl.logDir, "auth.log")
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()
    
    timestamp := time.Now().Format(time.RFC3339)
    status := "FAILED"
    if success {
        status = "SUCCESS"
    }
    entry := fmt.Sprintf("[%s] %s | %s | %s:%s | %s\n", timestamp, remoteAddr, status, username, password, status)
    f.WriteString(entry)
}

func (sl *SessionLogger) LogCommand(remoteAddr, username, command string) {
    filename := filepath.Join(sl.logDir, "commands.log")
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer f.Close()
    
    timestamp := time.Now().Format(time.RFC3339)
    entry := fmt.Sprintf("[%s] %s | %s | %s\n", timestamp, remoteAddr, username, command)
    f.WriteString(entry)
}
```

---

### Step 11: Run It

```bash
go run main.go
```

**Test the honeypot:**
```bash
ssh -p 2222 test@localhost
```

---

## Key Decisions

| Decision | Options | Recommendation |
|----------|---------|----------------|
| **Port** | 2222 or 22 | 2222 (safe, no sudo needed) |
| **Auth** | Accept all or reject some | Accept all (keep attacker engaged) |
| **Fake OS** | Ubuntu, CentOS, custom | Ubuntu (most common target) |
| **Commands** | Which to simulate | ls, cat, wget, curl, whoami, pwd, id |
| **Filesystem** | Static or dynamic | Static fake files (simpler) |
| **Download capture** | Save files or not | Save files (malware analysis) |

---

## Log Files Structure

```
logs/
├── auth.log          # Login attempts (username, password, IP)
├── commands.log      # Commands executed
└── sessions/         # Full session transcripts
    └── session_<timestamp>_<ip>.log
```

---

## Security Considerations

1. **Run in a container or VM** - Isolate the honeypot from your main system
2. **Don't run as root** - Use a non-privileged user
3. **Firewall rules** - Only expose the honeypot port
4. **Monitor disk usage** - Attackers may try to fill disk
5. **No real network access** - Block outbound connections from honeypot

---

## Next Steps / Enhancements

- [ ] Add fake filesystem with realistic directory structure
- [ ] Capture files attackers try to download
- [ ] Add rate limiting to prevent abuse
- [ ] Implement session recording (asciinema-style)
- [ ] Add real-time alerting for interesting activity
- [ ] Create web dashboard for viewing logs
- [ ] Add support for multiple honeypot instances

---

## Useful Commands for Testing

```bash
# Test basic connection
ssh -p 2222 root@localhost

# Test with specific username
ssh -p 2222 admin@localhost

# Test with password
sshpass -p 'test123' ssh -p 2222 root@localhost

# View logs in real-time
tail -f logs/auth.log
tail -f logs/commands.log
```

---

## Troubleshooting

**Connection refused:**
- Check if port is already in use: `lsof -i :2222`
- Check firewall rules: `sudo ufw status`

**SSH handshake fails:**
- Verify host key is properly loaded
- Check SSH library version compatibility

**No logs appearing:**
- Verify log directory exists and is writable
- Check that logging functions are being called

---

## Resources

- [golang.org/x/crypto/ssh documentation](https://pkg.go.dev/golang.org/x/crypto/ssh)
- [Cowrie honeypot (Python reference)](https://github.com/cowrie/cowrie)
- [SSH Protocol RFC](https://www.rfc-editor.org/rfc/rfc4253.txt)
