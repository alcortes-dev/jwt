package jwt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// HashingPassword generates a hash and salt for a given password.
//
// This function takes a string parameter `password`, which represents the
// password to be hashed. It generates a salt, which is a random string added
// to the password before hashing. The salt is generated using the current
// timestamp. The function returns three values:
// - `hash`: a string representing the hashed password
// - `salt`: a string representing the salt used for hashing
// - `error`: an error object if any error occurs during the hashing process
//
// The hashed password is generated using the SHA256 hashing algorithm. The
// salt is used to add randomness to the hashing process.
func HashingPassword(password string) (string, string, error) {
	if password == "" {
		return "", "", errors.New("empty password")
	}
	// Generate a salt using the current timestamp
	salt, err := hashing(password + fmt.Sprint(time.Now().UnixMicro()))
	if err != nil {
		return "", "", err
	}

	// Generate the hashed password by concatenating the password and the salt
	hash, err := hashing(password + salt)
	if err != nil {
		return "", "", err
	}

	// Return the hashed password and the salt
	return string(hash), salt, nil
}

// ValidatePassword validates a password by hashing it with the provided salt and comparing it to the given hash.
//
// Parameters:
// - password: a string representing the password to validate
// - salt: a string representing the salt used for hashing
// - hash: a string representing the hashed password to compare against
// Return type: bool
func ValidatePassword(password string, salt string, hash string) bool {
	result, err := hashing(password + salt)
	if err != nil {
		return false
	}
	return string(result) == hash
}

func hashing(payload string) (string, error) {
	h := sha256.New()
	_, err := h.Write([]byte(payload))
	if err != nil {
		return "", err
	}
	salt := h.Sum(nil)
	return string(salt), nil

}
