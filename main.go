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
	mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot))))

	// Register a handler for a readiness endpoint
	mux.HandleFunc("/healthz", readinessHandler)

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

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
