package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	"crypto/x509"
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
    _ = signer 
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
		go handleConnection(conn)
	}
	//accept connection and handle ssh handshake

	
	//listening on port 2222
	
	
	
}


func handleConnection (conn net.Conn){
    defer conn.Close()
    log.Printf("new connection from: %s", conn.RemoteAddr())
}