package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"os"
	"strings"
	"time"
)

/*
Constants

The following constants are used to specify the algorithm to sign the token.

- `HS256`: HMAC SHA256.
- `HS384`: HMAC SHA384.
- `HS512`: HMAC SHA512.
*/
const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
)

// JWT represents a JSON Web Token.
//
// A JSON Web Token is a compact and self-contained means of securely
// transmitting information as a JSON object. This information is
// signed by a sender and verified by a receiver using cryptographic
// techniques.
//
// The `JWT` struct contains a `JWTHeader` and a `JWTPayload`. The
// `JWTHeader` contains the algorithm used to sign the token and the
// type of the token. The `JWTPayload` contains the claims that are
// being transmitted.
type JWT struct {
	Header  JWTHeader  `json:"header"`
	Payload JWTPayload `json:"payload"`
}

// ProcessJWT generates a JSON Web Token (JWT) string by processing the header and payload of the given JWT struct.
//
// Parameters:
// - jwt: A pointer to a JWT struct containing the header and payload to be processed.
//
// Returns:
// - string: The generated JWT string in the format "header.payload.signature".
// - error: An error if any of the processing steps fail.
func (jwt *JWT) ProcessJWT() (string, error) {
	jwt.Payload.Iat = time.Now().Unix()
	header, err := processJWTHeader(&jwt.Header)
	if err != nil {
		return "", err
	}
	payload, err := processJWTPayload(&jwt.Payload)
	if err != nil {
		return "", err
	}
	jwtString := header + "." + payload

	signature, err := processHash(header, payload, jwt.Header.Alg)
	if err != nil {
		return "", err
	}
	jwtString = jwtString + "." + signature
	return jwtString, nil
}

func processHash(header string, payload string, alg string) (string, error) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		os.Setenv("JWT_SECRET_KEY", generateSecretKey())
		secretKey = os.Getenv("JWT_SECRET_KEY")
	}
	data := header + "." + payload
	key := []byte(secretKey)
	var h hash.Hash
	switch alg {
	case HS256:
		h = hmac.New(sha256.New, key)
	case HS384:
		h = hmac.New(sha512.New384, key)
	case HS512:
		h = hmac.New(sha512.New, key)

	}
	_, err := h.Write([]byte(data))
	if err != nil {
		return "", err
	}
	signature := h.Sum(nil)
	base64Result := base64.RawURLEncoding.EncodeToString(signature)
	return string(base64Result), nil
}

func generateSecretKey() string {
	h := sha256.New()
	h.Write([]byte(time.Now().String() + "alcortes"))
	secretKey := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return secretKey
}

func ValidateJWT(jwtString string) bool {
	jwtParts := strings.Split(jwtString, ".")
	if len(jwtParts) != 3 {
		return false
	}
	header, err := decodeJWTHeader(jwtParts[0])
	if err != nil {
		return false
	}
	signature, err := processHash(jwtParts[0], jwtParts[1], header.Alg)
	if err != nil {
		return false
	}
	if signature != jwtParts[2] {
		return false
	}
	return true
}

func PrintJWTContent(jwtString string) {
	jwtParts := strings.Split(jwtString, ".")
	header, err := decodeJWTHeader(jwtParts[0])
	if err != nil {
		return
	}
	payload, err := decodeJWTPayload(jwtParts[1])
	if err != nil {
		return
	}
	println(header.ToString())
	println(payload.ToString())
}

func (jwt *JWT) ToString() string {
	jwtString := "{" + jwt.Header.ToString() + "," + jwt.Payload.ToString() + "}"
	return jwtString
}
