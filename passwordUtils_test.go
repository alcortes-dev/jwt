package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestHashingPassword(t *testing.T) {
	// Test case 1: Valid password
	password := "password123"
	hashedPassword, salt, err := HashingPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}
	if hashedPassword == "" || salt == "" {
		t.Errorf("Empty hashed password or salt")
	}

	// Test case 2: Empty password
	hashedPassword2, salt2, err := HashingPassword("")
	if err == nil {
		t.Errorf("Expected error for empty password")
	}
	if hashedPassword2 != "" || salt2 != "" {
		t.Errorf("Expected empty hashed password and salt for empty password")
	}

	// Test case 3: Timestamp collision
	// Generate a salt using the current timestamp
	salt1, _ := hashing(password + fmt.Sprint(time.Now().UnixMicro()))
	// Generate a salt using a different timestamp
	timestamp := time.Now().Add(-time.Minute)
	salt2, _ = hashing(password + fmt.Sprint(timestamp.UnixMicro()))
	if salt1 == salt2 {
		t.Errorf("Expected different salts for different timestamps")
	}

	// Test case 4: Validate password
	// Valid password
	validPassword := "password123"
	if !ValidatePassword(validPassword, salt, hashedPassword) {
		t.Errorf("Expected password to be valid")
	}
	// Invalid password
	invalidPassword := "invalidpassword"
	if ValidatePassword(invalidPassword, salt, hashedPassword) {
		t.Errorf("Expected password to be invalid")
	}
}
