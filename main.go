package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/5tuartw/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

//"fmt"

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	const filepathRoot = "."
	const port = "8080"
	var apiCfg apiConfig

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Println("Error opening datacase:", err)
	}
	dbQueries := database.New(db)

	apiCfg.DB = dbQueries

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
	DB             *database.Queries
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
	var requestBody struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestBody)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Something went wrong decoding parameters")
		return
	}

	if len(requestBody.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := cleanUpChirp(requestBody.Body)
	response := struct {
		CleanedBody string `json:"cleaned_body"`
	}{
		CleanedBody: cleanedBody,
	}

	respondWithJSON(w, http.StatusOK, response)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResponse struct {
		Error string `json:"error"`
	}
	errorBody := errorResponse{Error: msg}
	dat, err := json.Marshal(errorBody)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)

}

func cleanUpChirp(msg string) string {
	profanities := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	// split the message into words
	msgWords := strings.Fields(msg)

	for i, word := range msgWords {
		lowercase := strings.ToLower(word)
		if profanities[lowercase] {
			msgWords[i] = "****"
		}
	}

	return strings.Join(msgWords, " ")
}
