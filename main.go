package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

type LoginAttempt struct {
	Time     string  `json:"time"`
	IP       string  `json:"IP"`
	User     string  `json:"user"`
	Password string  `json:"password"`
	Country  string  `json:"country"`
	City     string  `json:"city"`
	ISP      string  `json:"isp"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
}

type GeoLocation struct {
	Country string  `json:"country"`
	City    string  `json:"city"`
	ISP     string  `json:"isp"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

func loadHostKey(keyFile string) (ssh.Signer, error) {
	//step 1 try to read existing private key
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read key: %w", err)

		}
		//generate key
		keyBytes, err = generateHostKey(keyFile)
		if err != nil {
			return nil, err
		}
	}

	//if pvtkey exists then parse it
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key : %w", err)
	}

	return signer, nil
}

// if it pvt key doesnt exits then generate one
func generateHostKey(keyFile string) ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)

	if err != nil {
		return nil, fmt.Errorf("something went wrong %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(block)

	if pemBytes == nil {
		return nil, fmt.Errorf("failed to encode key to PEM")
	}

	if err != nil {
		return nil, fmt.Errorf("something went wrong %w", err)
	}
	err = os.WriteFile(keyFile, pemBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write key: %w", err)
	}
	return pemBytes, nil
}

func main() {

	go startApiServer("8080")
	//load or generate host key
	signer, err := loadHostKey("keys/host_key")
	if err != nil {
		log.Fatal(err)
	}
	//for json logging
	jsonLog, err := os.OpenFile("attacks.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)

	}
	defer jsonLog.Close()

	//logging and saving credentials
	logFile, err := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	config := configureSSHServer(signer, jsonLog)
	// _ = signer
	if err != nil {
		log.Fatal(err)
	}
	//configure ssh server
	//listen on tcp port
	listener, err := net.Listen("tcp", ":2223")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("server started on port :2223")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn, config)
	}
	//accept connection and handle ssh handshake
	//listening on port 2222
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !checkRateLimit(ip, 10, 20) {
		log.Printf("rate limit exceeded for IP: %s", ip)
		conn.Close()
		return
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("server handshake failed : %s", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel : %s ", err)
			return
		}
		go handleSessions(channel, requests, conn.RemoteAddr().String())
	}

	log.Printf("new connection from: %s", conn.RemoteAddr())
}

func configureSSHServer(signer ssh.Signer, jsonLog *os.File) *ssh.ServerConfig {

	config := &ssh.ServerConfig{}

	config.AddHostKey(signer)
	config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		log.Printf("login attempt - ip: %s user: %s password %s",
			conn.RemoteAddr(),
			conn.User(),
			string(password),
		)

		// geolocation thing
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		geo := getGeoLocation(ip)
		//geolocation thing
		entry := LoginAttempt{
			Time:     time.Now().UTC().Format(time.RFC3339),
			IP:       ip,
			User:     conn.User(),
			Password: string(password),
			Country:  geo.Country,
			City:     geo.City,
			ISP:      geo.ISP,
			Lat:      geo.Lat,
			Lon:      geo.Lon,
		}

		jsonBytes, err := json.Marshal(entry)
		if err == nil {
			jsonLog.Write(append(jsonBytes, '\n'))
		}
		return nil, nil
	}
	config.BannerCallback = func(conn ssh.ConnMetadata) string {
		return "Ubuntu 22.04.3 LTS\n"
	}
	return config
}

func handleSessions(channel ssh.Channel, requests <-chan *ssh.Request, remoteAddr string) {
	defer channel.Close()
	// go ssh.DiscardRequests(requests)

	go func() {
		for req := range requests {
			if req.Type == "shell" || req.Type == "pty-req" {
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		}
	}()

	//send fake prompt
	channel.Write([]byte("root@ubuntu:~# "))

	//read commands

	fakeFilesystem := map[string]string{
		"/etc/passwd":          "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"/etc/hosts":           "127.0.0.1\tlocalhost\n127.0.1.1\tubuntu",
		"/etc/hostname":        "ubuntu",
		"/home/ubuntu/.bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport LS_OPTIONS='--color=auto'\nalias ll='ls -lh'\nPS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '",
		"/proc/version":        "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-027) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU) 2.38) #101-Ubuntu SMP",
		"/proc/cpuinfo":        "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 23\nmodel\t\t: 1\nmodel name\t: AMD EPYC 7502P 32-Core Processor\n",
	}

	responses := map[string]string{
		"whoami":      "root",
		"id":          "uid=0(root) gid=0(root) groups=0(root)",
		"uname":       "Linux",
		"uname -a":    "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
		"uname -r":    "5.15.0-91-generic",
		"ls":          "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
		"ls -la":      "total 56\ndrwxr-xr-x   2 root root 4096 Mar 25 12:00 .\nddrwxr-xr-x  21 root root 4096 Mar 25 10:00 ..\ndrwxr-xr-x   2 root root 4096 Mar 25 12:00 bin\ndrwxr-xr-x   2 root root 4096 Mar 25 10:00 boot\ndrwxr-xr-x   5 root root    80 Mar 25 10:00 dev\ndrwxr-xr-x  95 root root 4096 Mar 25 12:00 etc\ndrwxr-xr-x   5 root root 4096 Mar 25 12:00 home\nlrwxrwxrwx   1 root root 4096 Jan 15 10:00 lib -> /usr/lib",
		"ls -l":       "total 56\ndrwxr-xr-x   2 root root 4096 Mar 25 12:00 bin\ndrwxr-xr-x   2 root root 4096 Mar 25 10:00 boot\ndrwxr-xr-x   5 root root    80 Mar 25 10:00 dev\ndrwxr-xr-x  95 root root 4096 Mar 25 12:00 etc\ndrwxr-xr-x   5 root root 4096 Mar 25 12:00 home",
		"pwd":         "/root",
		"hostname":    "ubuntu",
		"hostname -f": "ubuntu",
		"date":        "Wed Mar 25 12:00:00 UTC 2026",
		"uptime":      " 12:00:00 up 30 days, 1:45,  2 users,  load average: 0.15, 0.10, 0.05",
		"groups":      "root",
		"env":         "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nUSER=root\nSHELL=/bin/bash",
		"echo $PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"echo $HOME":  "/root",
		"echo $USER":  "root",
		"echo $SHELL": "/bin/bash",
		"printenv":    "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nUSER=root\nSHELL=/bin/bash",
		"ls /":        "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
		"ls /bin":     "bash  cat  cp  date  dd  df  echo  false  ls  mkdir  mv  pwd  rm  sh  sleep  true  uname",
		"ls /etc":     "passwd  hostname  hosts  profile  bashrc  resolv.conf",
		"ls /home":    "ubuntu",
		"ls /tmp":     "",
		"ls /var":     "cache  lib  local  lock  log  run  spool tmp",
		"ls /proc":    "1    2    3    cpuinfo    meminfo    version",
		"ls -1":       "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
		"clear":       "",
		"exit":        "logout",
		"logout":      "",
		"history":     "    1  uname -a\n    2  ls\n    3  pwd\n    4  whoami\n    5  id",
		"help":        "Available commands: ls, cd, pwd, whoami, id, uname, hostname, date, uptime, cat, echo, history, clear, exit",
	}
	var inputBuf strings.Builder
	for {
		buf := make([]byte, 1024)
		n, err := channel.Read(buf)
		if err != nil {
			if inputBuf.Len() > 0 {
				log.Printf("command received (partial): %s", inputBuf.String())
			}
			return
		}

		for _, b := range buf[:n] {
			if b == '\r' || b == '\n' {
				command := strings.TrimSpace(inputBuf.String())
				inputBuf.Reset()
				if command == "" {
					channel.Write([]byte("\r\nroot@ubuntu:~# "))
					continue
				}
				log.Printf("command received: %s", command)

				// Handle special commands
				if strings.HasPrefix(command, "cat ") {
					filename := strings.TrimSpace(strings.TrimPrefix(command, "cat "))
					if content, ok := fakeFilesystem[filename]; ok {
						channel.Write([]byte("\r\n" + content + "\r\nroot@ubuntu:~# "))
					} else if filename == "/etc/shadow" {
						channel.Write([]byte("\r\ncat: /etc/shadow: Permission denied\r\nroot@ubuntu:~# "))
					} else {
						channel.Write([]byte("\r\ncat: " + filename + ": No such file or directory\r\nroot@ubuntu:~# "))
					}
				} else if strings.HasPrefix(command, "cd ") {
					channel.Write([]byte("\r\nroot@ubuntu:~# "))
				} else if strings.HasPrefix(command, "echo ") {
					echoText := strings.TrimPrefix(command, "echo ")
					channel.Write([]byte("\r\n" + echoText + "\r\nroot@ubuntu:~# "))
				} else if strings.HasPrefix(command, "wget ") || strings.HasPrefix(command, "curl ") {
					log.Printf("download attempt from %s: %s", remoteAddr, command)
					channel.Write([]byte("\r\n--2026-03-25 12:00:00--  " + strings.TrimPrefix(strings.TrimPrefix(command, "wget "), "curl ") + "\nResolving... 192.168.1.1\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 12345 (12K) [text/plain]\nSaving to: 'index.html'\n\nindex.html          100%[===================>]  12.00K  --.-KB/s    in 0s\n\n2026-03-25 12:00:01 (123 MB/s) - 'index.html' saved [12345/12345]\r\nroot@ubuntu:~# "))
				} else if response, ok := responses[command]; ok {
					if command == "clear" {
						channel.Write([]byte("\033[2J\033[H\r\nroot@ubuntu:~# "))
					} else if command == "exit" || command == "logout" {
						channel.Write([]byte("logout\r\n"))
						return
					} else {
						channel.Write([]byte("\r\n" + response + "\r\nroot@ubuntu:~# "))
					}
				} else {
					channel.Write([]byte("\r\n" + command + ": command not found\r\nroot@ubuntu:~# "))
				}
			} else if b == 127 || b == 8 {
				if inputBuf.Len() > 0 {
					str := inputBuf.String()
					inputBuf.Reset()
					inputBuf.WriteString(str[:len(str)-1])
					channel.Write([]byte("\b \b"))
				}
			} else {
				inputBuf.WriteByte(b)
				channel.Write([]byte{b})
			}
		}
	}
}

//getting some GeoLocation
//

func getGeoLocation(ip string) GeoLocation {
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		log.Printf("error making http request: %v", err)
		return GeoLocation{}
	}

	defer resp.Body.Close()

	var geo GeoLocation
	err = json.NewDecoder(resp.Body).Decode(&geo)
	if err != nil {
		log.Printf("geolocation failed: %v", err)
		return GeoLocation{}
	}
	return geo
}

var (
	rateLimiters = make(map[string]*rate.Limiter)
	rateMu       sync.Mutex
)

func checkRateLimit(ip string, rps float64, burst int) bool {
	rateMu.Lock()
	defer rateMu.Unlock()

	limiter, exists := rateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(rps), burst)
		rateLimiters[ip] = limiter
		return true
	}
	return limiter.Allow()
}
