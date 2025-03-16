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
	"time"

	"github.com/5tuartw/chirpy/internal/auth"

	"github.com/5tuartw/chirpy/internal/database"
	"github.com/google/uuid"
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
	if os.Getenv("PLATFORM") == "dev" {
		apiCfg.isDev = true
	} else {
		apiCfg.isDev = false
	}
	apiCfg.JWTSecret = os.Getenv("JWT_SECRET")

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
	mux.HandleFunc("POST /admin/resethits", apiCfg.resetHitsHandler)

	// Register a handler for validate_chirpy
	//mux.HandleFunc("POST /api/validate_chirp", apiCfg.validateReqHandler) // functionality moved to addChirp

	// Register a handler for creating users
	mux.HandleFunc("POST /api/users", apiCfg.createUser)

	// Register a handler for resetting users
	mux.HandleFunc("POST /admin/reset", apiCfg.resetAllUsers)

	// Registers a handler for creating Chirps
	mux.HandleFunc("POST /api/chirps", apiCfg.addChirp)

	// Reigster a handler to get all Chirps
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)

	// Get specific Chirp
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)

	// Handle logins
	mux.HandleFunc("POST /api/login", apiCfg.login)

	// Refresh token
	mux.HandleFunc("POST /api/refresh", apiCfg.refresh)

	// Revoke token
	mux.HandleFunc("POST /api/revoke", apiCfg.revoke)

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
	isDev          bool
	JWTSecret      string
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

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (c *apiConfig) addChirp(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestBody)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Something went wrong decoding parameters")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized, cannot get token")
		return
	}

	tokenUserID, err := auth.ValidateJWT(token, c.JWTSecret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized, cannot validate: "+err.Error())
		return
	}

	if len(requestBody.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := cleanUpChirp(requestBody.Body)

	chirp, err := c.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: tokenUserID,
	})

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create chirp")
		return
	}

	formattedChirp := formatChirp(chirp)

	respondWithJSON(w, 201, formattedChirp)

}

func formatChirp(chirp database.Chirp) Chirp {
	formattedChirp := Chirp{
		ID:        chirp.ID,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
	}
	return formattedChirp
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

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (c *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&requestBody)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error decoding json data")
		return
	}

	if requestBody.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if requestBody.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	hashedPword, err := auth.HashPassword(requestBody.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create hashed password")
		return
	}

	user, err := c.DB.CreateUser(r.Context(), database.CreateUserParams{
		Email:          requestBody.Email,
		HashedPassword: string(hashedPword),
	})

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error adding user to database")
		return
	}

	userData := User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	respondWithJSON(w, 201, userData)

}

func (c *apiConfig) resetAllUsers(w http.ResponseWriter, r *http.Request) {
	if !c.isDev {
		respondWithError(w, 403, "Forbidden database action")
		return
	}

	err := c.DB.DeleteAllUsers(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error resetting users")
		return
	}

	type response struct {
		Message string `json:"message"`
	}
	respondWithJSON(w, 200, response{Message: "Users table has been reset"})
}

func (c *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

	chirps, err := c.DB.GetChirps(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not fetch Chirps")
		return
	}

	allChirps := []Chirp{}
	for _, chirp := range chirps {
		allChirps = append(allChirps, formatChirp(chirp))
	}
	respondWithJSON(w, 200, allChirps)
}

func (c *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not parse Chirp ID")
		return
	}
	chirp, err := c.DB.GetChirp(r.Context(), id)
	if err != nil {
		respondWithError(w, 404, "Unable to fetch Chirp")
		return
	}
	respondWithJSON(w, 200, formatChirp(chirp))
}

type TokenUser struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

func (c *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&requestBody)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error decoding json data")
		return
	}

	if requestBody.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if requestBody.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	const oneHourInSeconds int64 = 3600

	user, err := c.DB.GetUserByEmail(r.Context(), requestBody.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}
	err = auth.CheckPasswordHash(requestBody.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	token, err := auth.MakeJWT(user.ID, c.JWTSecret, time.Duration(oneHourInSeconds)*time.Second)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "could not create access token")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "could not create refresh token")
		return
	}
	sixtyDaysInSeconds := 60 * 60 * 24 * 60
	expiry := time.Now().Add(time.Duration(sixtyDaysInSeconds) * time.Second)
	rToken, err := c.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: expiry,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not add new token to database")
		return
	}

	thisRToken := rToken.Token

	userData := TokenUser{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: thisRToken,
	}

	respondWithJSON(w, 200, userData)

}

func (c *apiConfig) refresh(w http.ResponseWriter, r *http.Request) {
	var responseBody struct {
		Token string `json:"token"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized, cannot get token")
		return
	}

	rToken, err := c.DB.GetRefreshToken(r.Context(), token)
	if err != nil {
		respondWithError(w, 401, "No valid token found")
		return
	}

	// Check if token is expired
	if time.Now().After(rToken.ExpiresAt) {
		respondWithError(w, 401, "Token expired")
		return
	}

	// Check if token is revoked
	if rToken.RevokedAt.Valid {
		respondWithError(w, 401, "Token revoked")
		return
	}

	const oneHourInSeconds int64 = 3600
	accessToken, err := auth.MakeJWT(rToken.UserID, c.JWTSecret, time.Duration(oneHourInSeconds)*time.Second)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "could not create access token")
		return
	}

	responseBody.Token = accessToken
	respondWithJSON(w, 200, responseBody)
}

func (c *apiConfig) revoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized, cannot get token")
		return
	}
	
	// Check if the token exists first
	rToken, err := c.DB.GetRefreshToken(r.Context(), token)
	if err != nil {
		respondWithError(w, 401, "No valid token found")
		return
	}

	// Check if token is already revoked
	if rToken.RevokedAt.Valid {
		respondWithError(w, 400, "Token already revoked")
		return
	}

	// Now attempt to revoke the token
	err = c.DB.RevokeToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not revoke token")
		return
	}

	w.WriteHeader(204)
}
