package main

import (
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
		//key exists
		signer,err := ssh.ParsePrivateKey(keyBytes)
		if err == nil {
			return signer,nil
		}
	}	
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