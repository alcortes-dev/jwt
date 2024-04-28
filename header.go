package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// JWTHeader is a struct that represents the header of a JSON Web Token.
//
// It contains the algorithm used to sign the token and the token type.
// Both fields are mandatory and have specific values.
//
// The `Alg` field is a string that represents the algorithm used to sign the token.
// The possible values are `HS256`, `HS384` and `HS512`.
//
// The `Typ` field is a string that represents the token type.
// The possible value is `JWT`.
type JWTHeader struct {
	Alg string `json:"alg"` // Required. Possible values: HS256, HS384, HS512.
	Typ string `json:"typ"` // Required. Possible value: JWT.
}

func processJWTHeader(jwtHeader *JWTHeader) (string, error) {
	headerJson, err := json.Marshal(jwtHeader)
	if err != nil {
		return "", err
	}
	base64Header := base64.RawURLEncoding.EncodeToString(headerJson)
	return base64Header, nil
}
