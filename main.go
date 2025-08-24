package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Err loading .env file")
	}

	var loadErr error
	userSchema, loadErr := loadSchema("schemas/user.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}

	projectSchema, loadErr := loadSchema("schemas/project.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}

	connStr := os.Getenv("POSTGRES_CONN_URL")
	if len(connStr) == 0 {
		log.Fatal("POSTGRES_CONN_URL env variable is not set or empty")
	}

	jwtKey := []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(jwtKey) == 0 {
		log.Fatal("JWT_SECRET_KEY env variable is not set or empty")
	}

	DB, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Cannot connect to pg.", err)
	}
	DB.Ping()
	defer DB.Close()

	app := App{DB: DB, JWTKey: jwtKey}

	log.Println("Starting server...")
	router := mux.NewRouter()

	log.Println("Setting up routes...")

	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
	router.Handle("/login", userChain.ThenFunc(app.Login)).Methods("POST")
	router.Handle("/register", userChain.ThenFunc(app.Register)).Methods("POST")

	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware, validateMiddleware(projectSchema))
	router.Handle("/projects", alice.New(loggingMiddleware, app.jwtMiddleware).ThenFunc(app.GetProjects)).Methods("GET")
	router.Handle("/projects", projectChain.ThenFunc(app.CreateProject)).Methods("POST")
	router.Handle("/projects/{id}", alice.New(loggingMiddleware, app.jwtMiddleware).ThenFunc(app.GetProject)).Methods("GET")
	router.Handle("/projects/{id}", projectChain.ThenFunc(app.UpdateProject)).Methods("PUT")
	router.Handle("/projects/{id}", alice.New(loggingMiddleware, app.jwtMiddleware).ThenFunc(app.DeleteProject)).Methods("DELETE")

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-type", "application/json")

		json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!"})
	}).Methods("GET")

	log.Println("Listining on port 5001")
	log.Fatal(http.ListenAndServe(":5001", router))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s ", r.RemoteAddr, r.Method, r.URL)

		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if len(authHeader) == 0 {
			RespondWithError(w, http.StatusUnauthorized, "No token provided")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		var claims Claims
		token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				RespondWithError(w, http.StatusUnauthorized, "Invalid token signature")
				return
			}
			log.Println(err)
			RespondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}
		if !token.Valid {
			RespondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				log.Println(err)
				RespondWithError(w, http.StatusBadRequest, "Invalid request paload")
				return
			}

			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				log.Println(err)
				RespondWithError(w, http.StatusBadRequest, "Invalid request paload")
				return
			}

			schemaLoader := gojsonschema.NewStringLoader(schema)

			documentLoader := gojsonschema.NewGoLoader(body)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				log.Println(err)
				RespondWithError(w, http.StatusInternalServerError, "Error validating JSON")
				return
			}

			if !result.Valid() {
				var errs []string
				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}
				log.Println(errs)
				RespondWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}

// loadSchema loads a json schema from a file path
func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	XataID   string `json:"xata_id"`
	jwt.RegisteredClaims
}

type UserResponse struct {
	XataID   string `json:"xata_id"`
	Username string `json:"username"`
	Token    string `json:"token,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

func RespondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func (app *App) generateToken(username, xataID string) (string, error) {
	expirationTime := time.Now().Add(30 * time.Minute)

	claims := &Claims{
		Username: username,
		XataID:   xataID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(app.JWTKey)
}

// register function to handle user registration
func (app *App) Register(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}

	var xataID string
	err = app.DB.QueryRow("INSERT INTO \"users\" (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, string(hashPassword)).Scan(&xataID)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusInternalServerError, "Error inserting user")
		return
	}
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username})
}

// login function to handle user login
func (app *App) Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var storedCreds Credentials
	var xataID string
	err = app.DB.QueryRow("select username, password, xata_id from \"users\" where username = $1", creds.Username).Scan(&storedCreds.Username, &storedCreds.Password, &xataID)
	if err != nil {
		if err == sql.ErrNoRows {
			RespondWithError(w, http.StatusUnauthorized, "Bad credentials")
			return
		}
		log.Fatal(err)
		RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	bytesFromPassword := []byte(creds.Password)
	bytesFromStoredPassword := []byte(storedCreds.Password)
	err = bcrypt.CompareHashAndPassword(bytesFromStoredPassword, bytesFromPassword)
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "Bad credentials")
		return
	}

	tokenString, err := app.generateToken(creds.Username, xataID)
	if err != nil {
		log.Fatal(err)
		RespondWithError(w, http.StatusUnauthorized, "Error generating the token")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})
}

type RouteResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func (app *App) CreateProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!"})
}

func (app *App) UpdateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")

	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}

func (app *App) GetProjects(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}

func (app *App) GetProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}

func (app *App) DeleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}
