package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

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
	}
	
	 
		signer,err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil,fmt.Errorf("failed to parse key : %w",err)
		}

		return signer,nil
}


func generateHostKey(keyFile string) ([]byte,error){
	_,privateKey,err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil,fmt.Errorf("something went wrong %w",err)
	}
	
	
	derBytes,err:= x509.MarshalPKCS8PrivateKey(privateKey) 

	if err != nil {
		return nil,fmt.Errorf("something went wrong %w",err)
	}


	block := &pem.Block{
		Type: "OPENSSH PRIVATE KEY",
		 Bytes: derBytes, 
	}

	pemBytes := pem.EncodeToMemory(block) 
	 

	if err := pem.Encode(os.Stdout, block); err != nil {
		log.Fatal(err)
	}
	
	if err != nil {
		return nil,fmt.Errorf("something went wrong %w",err)
	}

	return nil,pemBytes
}

func main(){
	//load or generate host key
	//configure ssh server
	//listen on tcp port
	//accept connection and handle ssh handshake


	//listening on port 2222
	http.HandleFunc("/",func(w http.ResponseWriter, r *http.Request){

	})
	
	log.Fatal(http.ListenAndServe(":2222",nil))
}