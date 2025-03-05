package main

import (
	//"fmt"
	"log"
	"net/http"
)

func main() {
	const filepathRoot = "."
	const port = "8080"

	mux := http.NewServeMux()
	// Define FileServer as handler
	mux.Handle("/", http.FileServer(http.Dir(filepathRoot)))

	// Initialise the http.Server
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Start the server
	log.Printf("Starting server on :%s", port)
	if err := server.ListenAndServe(); err != nil {
		log.Println("Serverfailed:", err)
	}
}
