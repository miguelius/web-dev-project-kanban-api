package auth

import (
	"encoding/json"
	"net/http"
)

type RouteResponse struct {
	Message string `json:"message"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")

	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!"})
}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")

	json.NewEncoder(w).Encode(RouteResponse{Message: "Hola, guachín!"})
}
