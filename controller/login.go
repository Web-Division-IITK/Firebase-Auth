package controller

import (
	"backend/model"
	"backend/utils"
	"context"
	"encoding/json"
	"log"
	"net/http"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user model.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Authenticate user with Firebase Authentication
	u, err := utils.FirebaseAuth.GetUserByEmail(context.Background(), user.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		log.Printf("Failed to get user: %v\n", err)
		return
	}

	if !u.EmailVerified {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		log.Printf("Email not verified for user: %v\n", user.Email)
		return
	}

	// Successful login
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User logged in successfully"))
}
