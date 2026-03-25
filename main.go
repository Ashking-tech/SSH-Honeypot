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
	"os"
	"strings"
	"time"
	"net/http"

	"golang.org/x/crypto/ssh"
)


type LoginAttempt struct {
	Time    string `json:"time"`
	IP    string `json:"IP"`
	User    string `json:"user"`
	Password    string `json:"password"`
	Country string `json:"country"`
	City string `json:"city"`
	ISP string `json:"isp"`
	Lat     float64 `json:"lat"`
    Lon     float64 `json:"lon"`
}	

type GeoLocation struct {
	Country string `json:"country"`
	City string `json:"city"`
	ISP string `json:"isp"`
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
	jsonLog,err := os.OpenFile("attacks.json",os.O_APPEND|os.O_CREATE|os.O_WRONLY,0644)
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

	config := configureSSHServer(signer,jsonLog)
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
	log.Println("server started on port :2222")

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
		go handleSessions(channel, requests)
	}

	log.Printf("new connection from: %s", conn.RemoteAddr())
}

func configureSSHServer(signer ssh.Signer,jsonLog *os.File) *ssh.ServerConfig {
	
	config := &ssh.ServerConfig{}
	
	config.AddHostKey(signer)
	config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		log.Printf("login attempt - ip: %s user: %s password %s",
			conn.RemoteAddr(),
			conn.User(),
			string(password),
		)
		
//geolocation thing
ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		geo := getGeoLocation(ip)
//geolocation thing
		entry := LoginAttempt{
    			Time:     time.Now().UTC().Format(time.RFC3339),
       			IP:       ip,
          		User:     conn.User(),
            	Password: string(password),
             	Country: geo.Country,
              	City: geo.City,
               	ISP: geo.ISP,
                Lat:     geo.Lat,
                Lon:     geo.Lon,
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

func handleSessions(channel ssh.Channel, requests <-chan *ssh.Request) {
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

	responses := map[string]string{
		"whoami":   "root",
		"id":       "uid=0(root) gid=0(root) groups=0(root)",
		"uname -a": "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
		"ls":       "bin  boot  dev  etc  home  lib  usr  var",
		"pwd":      "/root",
	}
	buf := make([]byte, 1024)
	var inputBuf strings.Builder
	for {
		n, err := channel.Read(buf)
		if err != nil {
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
				if response, ok := responses[command]; ok {
					channel.Write([]byte("\r\n" + response + "\r\nroot@ubuntu:~# "))
				} else {
					channel.Write([]byte("\r\ncommand not found\r\nroot@ubuntu:~# "))
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
 
func getGeoLocation(ip string)GeoLocation {
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		log.Printf("error making http request: %v",err)
		return GeoLocation{}
	}
	
	defer resp.Body.Close()
	
	var geo GeoLocation
	err = json.NewDecoder(resp.Body).Decode(&geo)
	if err != nil {
		log.Printf("geolocation failed: %v",err)
		return GeoLocation{}
	}
	return geo
}