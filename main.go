package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func loadHostKey(keyFile string) (ssh.Signer,error){
	//step 1 try to read existing private key
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		if !os.IsNotExist(err){
			return nil,fmt.Errorf("failed to read key: %w",err)
			
		}
		//generate key
		keyBytes,err = generateHostKey(keyFile)
		if err != nil {
			return nil, err
		}
	}
	
	//if pvtkey exists then parse it 
		signer,err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil,fmt.Errorf("failed to parse key : %w",err)
		}

		return signer,nil
}

//if it pvt key doesnt exits then generate one
func generateHostKey(keyFile string) ([]byte,error){
	_,privateKey,err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
    return nil, fmt.Errorf("failed to generate key: %w", err)
}
	derBytes,err:= x509.MarshalPKCS8PrivateKey(privateKey) 

	if err != nil {
		return nil,fmt.Errorf("something went wrong %w",err)
	}
	block := &pem.Block{
		Type: "PRIVATE KEY",
		 Bytes: derBytes, 
	}

	pemBytes := pem.EncodeToMemory(block) 
	 
if pemBytes == nil {
	return nil, fmt.Errorf("failed to encode key to PEM")
}
	
	if err != nil {
		return nil,fmt.Errorf("something went wrong %w",err)
	}
	return pemBytes,nil
}




func main(){
	//load or generate host key
	signer,err := loadHostKey("host_key")
	
	//logging and saving credentials
	logFile,err := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY,0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout,logFile))
	
	config := configureSSHServer(signer)
    // _ = signer 
	if err != nil {
		log.Fatal(err)
	}	
	//configure ssh server
	//listen on tcp port
	listener,err := net.Listen("tcp",":2222")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("server started on port :2222")
	
	for {
		conn,err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn,config)
	}
	//accept connection and handle ssh handshake
	//listening on port 2222
}



func handleConnection (conn net.Conn,config *ssh.ServerConfig){
	sshConn, chans, reqs, err := ssh.NewServerConn(conn,config)
	if err != nil {
		log.Printf("server handshake failed : %s",err)
		return
	}
    defer sshConn.Close()
    go ssh.DiscardRequests(reqs)
    for newChannel := range chans {
    	if newChannel.ChannelType() != "session" {
    	newChannel.Reject(ssh.UnknownChannelType,"unknown channel type")
    	continue
     }
     
     channel,requests,err := newChannel.Accept()
     if err != nil {
      log.Printf("could not accept channel : %s ",err)
      return 
     }
     go handleSessions(channel,requests)
    }
    
    log.Printf("new connection from: %s", conn.RemoteAddr())
}

func configureSSHServer(signer ssh.Signer) *ssh.ServerConfig {
	config := &ssh.ServerConfig{}
	config.AddHostKey(signer)
	config.PasswordCallback = func(conn ssh.ConnMetadata,password []byte)(*ssh.Permissions,error){
		log.Printf("login attempt - ip: %s user: %s password %s",
			conn.RemoteAddr(),
			conn.User(),
			string(password),
		)
		return nil,nil
	}
	
	return config
}

func handleSessions(channel ssh.Channel,requests <-chan *ssh.Request){
	defer channel.Close()
	// go ssh.DiscardRequests(requests)
	
	go func(){
    	for req := range requests {
     	if req.Type == "shell" || req.Type == "pyt-req"{
      		req.Reply(true,nil)
      }else{
      req.Reply(false,nil)
      }
     }
    }()
	
	//send fake prompt
	channel.Write([]byte("root@ubuntu:~#"))
	
	//read commands
	
	buf := make([]byte,1024)
	for {
		n,err := channel.Read(buf)
		if err != nil {
			return
		}
		command := string(buf[:n])
		log.Printf("command recieved: %s ",command)
		// channel.Write([]byte("command not found\r\nroot@ubuntu:~# "))
		responses := map[string]string {
		"whoami":   "root",
    	"id":       "uid=0(root) gid=0(root) groups=0(root)",
     	"uname -a": "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
      	"ls":       "bin  boot  dev  etc  home  lib  usr  var",
       	"pwd":      "/root",
		}
		
		command = strings.TrimSpace(string(buf[:n]))
		log.Printf("command recieved : %s",command)
		
		if responses, ok := responses[command]; ok {
			channel.Write([]byte(responses + "\r\nroot@ubuntu:~# "))
		}else{
			channel.Write([]byte("command not found\r\nroot@ubuntu:~#"))
		}
	}
}