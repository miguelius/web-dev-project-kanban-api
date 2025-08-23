package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/m6io/web-dev-project-kanban-api/auth"
	"github.com/m6io/web-dev-project-kanban-api/projects"
)

type RouteResponse struct {
	Message string `json:"message"`
}

func main() {
	log.Println("Starting server...")
	router := mux.NewRouter()

	log.Println("Setting up routes...")

	router.Handle("/login", alice.New(loggingMiddleware).ThenFunc(auth.Login)).Methods("POST")
	router.Handle("/register", alice.New(loggingMiddleware).ThenFunc(auth.Register)).Methods("POST")
	router.Handle("/projects", alice.New(loggingMiddleware).ThenFunc(projects.GetProjects)).Methods("GET")
	router.Handle("/projects", alice.New(loggingMiddleware).ThenFunc(projects.CreateProject)).Methods("POST")
	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(projects.GetProject)).Methods("GET")
	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(projects.UpdateProject)).Methods("PUT")
	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(projects.DeleteProject)).Methods("DELETE")

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
