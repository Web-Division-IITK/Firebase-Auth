package utils

import (
	"context"
	"fmt"
	"net/smtp"
	"net/url"
	"os"

	"firebase.google.com/go/auth"
)

// SendEmail Function to send email
func SendEmail(to, subject, body string) error {
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

func SendVerificationEmail(user *auth.UserRecord) error {
	// Generate email verification link with settings
	settings := &auth.ActionCodeSettings{
		URL:             fmt.Sprintf("https://%s.firebaseapp.com/", os.Getenv("FIREBASE_PROJECT_ID")),
		HandleCodeInApp: true,
	}
	// Send email with the verification link
	link, err := FirebaseAuth.EmailVerificationLinkWithSettings(context.Background(), user.Email, settings)
	if err != nil {
		return fmt.Errorf("error generating email verification link: %v", err)
	}
	// Log the verification link
	fmt.Printf("Verification link for user %s: %s\n", user.Email, link)

	// Construct the email body with the link
	body := fmt.Sprintf("%s\n%s", "Please click the following link to verify.", url.QueryEscape(link))
	// Replace recipientEmail with the actual email address of the user
	recipientEmail := user.Email

	// Call the sendEmail function to send the email
	err = SendEmail(recipientEmail, "Verify your email address", body)
	if err != nil {
		return fmt.Errorf("error sending email: %v", err)
	}

	fmt.Println("Verification email sent successfully")

	return nil
}
