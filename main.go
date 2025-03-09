package main

import (
	//"fmt"
	//"fmt"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

func main() {
	const filepathRoot = "."
	const port = "8080"
	var apiCfg apiConfig

	mux := http.NewServeMux()
	// Define FileServer as handler
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))

	// Register a handler for a readiness endpoint
	mux.HandleFunc("GET /api/healthz", readinessHandler)

	// Register a handler for hitcount requests
	mux.HandleFunc("GET /admin/metrics", apiCfg.hitcountHandler)

	// Register a handler for hitcount reset
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHitsHandler)

	// Register a handler for validate_chirpy
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.validateReqHandler)

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

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (c *apiConfig) hitcountHandler(w http.ResponseWriter, r *http.Request) {
	//get the current hits
	hits := c.fileserverHits.Load()
	//responseText := fmt.Sprintf("Hits: %d", hits)

	// Read the metrics.html template file
	templateBytes, err := os.ReadFile("metrics.html")
	if err != nil {
		http.Error(w, "Internal Server Error: Could not read template", http.StatusInternalServerError)
		log.Printf("Error reading metrics.html: %v", err)
		return
	}

	// Parse the HTML template
	tmpl, err := template.New("metrics").Parse(string(templateBytes))
	if err != nil {
		http.Error(w, "Internal Server Error: Could not parse template", http.StatusInternalServerError)
		log.Printf("Error parsing metrics.html: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	err = tmpl.Execute(w, map[string]int64{"Hits": int64(hits)})
	if err != nil {
		http.Error(w, "Internal Server Error: Could not execute template", http.StatusInternalServerError)
		log.Printf("Error executing template: %v", err)
		return
	}
}

func (c *apiConfig) resetHitsHandler(w http.ResponseWriter, r *http.Request) {
	c.fileserverHits.Store(0)
	responseText := "Hit counter has been reset."

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(responseText))
}

func (c *apiConfig) validateReqHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	type validResponse struct {
		Valid bool `json:"valid"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		errorBody := errorResponse{Error: "Something went wrong decoding parameters"}
		dat, err := json.Marshal(errorBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write(dat)
		return
	}
	if len(params.Body) > 140 {
		errorBody := errorResponse{Error: "Chirp is too long"}
		dat, err := json.Marshal(errorBody)
		if err != nil {
			w.WriteHeader(500)
			log.Printf("Error marshalling JSON: %s", err)
			return
		}
		w.WriteHeader(400)
		w.Write(dat)
		return
	}

	respBody := validResponse{Valid: true}
	dat, err := json.Marshal(respBody)
	if err != nil {
		w.WriteHeader(500)
		log.Printf("Error marshalling JSON: %s", err)
		return
	}
	w.WriteHeader(200)
	w.Write(dat)
}

func (c *apiConfig) validateRespHandler(w http.ResponseWriter, r *http.Request) {

}
