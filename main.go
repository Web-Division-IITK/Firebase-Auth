package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"net/smtp"

	"github.com/joho/godotenv"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"firebase.google.com/go/db"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/option"
)

var (
	firebaseAuth *auth.Client
	firebaseDB   *db.Client
)

func main() {
	// Initialize Firebase Auth and Database clients
	initFirebase()

	r := mux.NewRouter()

	// Register routes
	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")

	// Start server
	fmt.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func initFirebase() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v\n", err)
	}

	opt := option.WithCredentialsFile("notification-22d59-firebase-adminsdk-wwfab-12d295b4ca.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("Error initializing Firebase app: %v\n", err)
	}

	firebaseAuth, err = app.Auth(context.Background())
	if err != nil {
		log.Fatalf("Error initializing Firebase Auth client: %v\n", err)
	}

	// Get the database URL from the environment variables
	databaseURL := os.Getenv("FIREBASE_DATABASE_URL")
	if databaseURL == "" {
		log.Fatalf("FIREBASE_DATABASE_URL not set in .env file")
	}

	// Initialize the Firebase Database client with the database URL
	firebaseDB, err = app.DatabaseWithURL(context.Background(), databaseURL)
	if err != nil {
		log.Fatalf("Error initializing Firebase Database client: %v\n", err)
	}
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		log.Printf("Failed to hash password: %v\n", err)
		return
	}

	params := (&auth.UserToCreate{}).
		Email(user.Email).
		Password(string(hashedPassword)).
		DisplayName(user.Role) // Assuming Role is used as DisplayName for simplicity

	newUser, err := firebaseAuth.CreateUser(context.Background(), params)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		log.Printf("Failed to create user: %v\n", err)
		return
	}

	err = sendVerificationEmail(newUser)
	if err != nil {
		http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		log.Printf("Failed to send verification email: %v\n", err)
		return
	}

	// Assign role to the user in Firebase Database
	err = firebaseDB.NewRef("users/"+newUser.UID+"/role").Set(context.Background(), user.Role)
	if err != nil {
		http.Error(w, "Failed to assign role to user", http.StatusInternalServerError)
		log.Printf("Failed to assign role to user: %v\n", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

func sendVerificationEmail(user *auth.UserRecord) error {
	// Generate email verification link with settings
	settings := &auth.ActionCodeSettings{
		URL:             "https://notification-22d59.firebaseapp.com/",
		HandleCodeInApp: true,
	}
	// Send email with the verification link
	link, err := firebaseAuth.EmailVerificationLinkWithSettings(context.Background(), user.Email, settings)
	if err != nil {
		return fmt.Errorf("error generating email verification link: %v", err)
	}

	// Log the verification link
	fmt.Printf("Verification link for user %s: %s\n", user.Email, link)

	// Construct the email body with the link
	body := "Please click on the following link to verify your email address:\n" + link

	// Replace recipientEmail with the actual email address of the user
	recipientEmail := user.Email

	// Call the sendEmail function to send the email
	err = sendEmail(recipientEmail, "Verify your email address", body)
	if err != nil {
		return fmt.Errorf("error sending email: %v", err)
	}

	fmt.Println("Verification email sent successfully")

	return nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Authenticate user with Firebase Authentication
	u, err := firebaseAuth.GetUserByEmail(context.Background(), user.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		log.Printf("Failed to get user: %v\n", err)
		return
	}

	if u.EmailVerified == false {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		log.Printf("Email not verified for user: %v\n", user.Email)
		return
	}

	// Successful login
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User logged in successfully"))
}

// Function to send email
func sendEmail(to, subject, body string) error {
	// SMTP configuration
	smtpHost := "smtp.gmail.com"
	smtpPort := 587
	smtpUsername := os.Getenv("SMTP_USERNAME")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	from := smtpUsername

	// Constructing email headers
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=\"utf-8\""
	headers["Content-Transfer-Encoding"] = "quoted-printable"

	// Compose the email message
	var msg string
	for key, value := range headers {
		msg += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	msg += "\r\n" + body

	// Connect to the SMTP server with TLS
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpHost, smtpPort), auth, from, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}
