package projects

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

type RouteResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func CreateProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!"})
}

func UpdateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")

	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}

func GetProjects(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}

func GetProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}

func DeleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!", ID: id})
}
