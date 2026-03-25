package main

import (
	"bufio"
	"encoding/json"
	
	"log"
	"net/http"
	"os"
)

func attacksHandler(w http.ResponseWriter, r *http.Request) {
    file, err := os.Open("attacks.json")
    if err != nil {
        http.Error(w, "could not read attacks file", http.StatusInternalServerError)
        return
    }
    defer file.Close()

    var attacks []LoginAttempt
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        var entry LoginAttempt
        err := json.Unmarshal(scanner.Bytes(), &entry)
        if err != nil {
            continue
        }
        attacks = append(attacks, entry)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(attacks)
}

//struct for sending json response

type StatEntry struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type StatsResponse struct {
	TopPasswords []StatEntry `json:"top_passwords"`
	TopUsers 	 []StatEntry `json:"top_users"`
	TopCountries []StatEntry `json:"top_countries"`
}

func statsHandler(w http.ResponseWriter,r *http.Request){
	
	file, err := os.Open("attacks.json")
	if err != nil {
		http.Error(w,"could not read the file",http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	
	Passwords := make(map[string]int)
	users := make(map[string]int)
	countries := make(map[string]int)
	
	for scanner.Scan(){
		var entry LoginAttempt
		
		err:= json.Unmarshal(scanner.Bytes(),&entry)
		if err != nil{
			http.Error(w,"had trouble reading the json",http.StatusInternalServerError)
			return
		}
		Passwords[entry.Password]++
		users[entry.User]++
		countries[entry.Country]++
		}
		
		var stats StatsResponse
		
		for k, v := range Passwords {
			entry := StatEntry{Value: k, Count: v}
    		stats.TopPasswords = append(stats.TopPasswords, entry)
		}
		
		
		for k, v := range users {
			entry := StatEntry{Value: k, Count: v}
    		stats.TopUsers = append(stats.TopUsers, entry)
		}
		
		
		for k, v := range countries {
			entry := StatEntry{Value: k, Count: v}
    		stats.TopCountries = append(stats.TopCountries, entry)
		}
		
		w.Header().Set("Content-Type","application/json")
		json.NewEncoder(w).Encode(stats)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "dashboard.html")
}


func startApiServer(port string){
	// sets up HTTP routes and listens on port 8090
	http.HandleFunc("/api/attacks",attacksHandler)
	http.HandleFunc("/",dashboardHandler)
    http.HandleFunc("/api/stats", statsHandler)
	log.Printf("server starting on port %s\n",port)
	err := http.ListenAndServe(":"+port,nil)
	if err != nil {
		log.Fatal(err)
	}
	
	// a handler for GET /api/attacks that reads attacks.json and returns it
	// a handler for GET /api/stats that compute top passwords,usernames,countries
}

