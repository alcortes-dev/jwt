package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

func NewJWTHeader(alg string) *JWTHeader {
	var localAlg string = HS256
	algUpper := strings.ToUpper(alg)
	if (algUpper == HS256) || (algUpper == HS384) || (algUpper == HS512) {
		localAlg = algUpper
	}
	return &JWTHeader{
		Alg: localAlg,
		Typ: "JWT",
	}
}

func (jwtHeader *JWTHeader) Marshal() (string, error) {
	headerJson, err := json.Marshal(jwtHeader)
	if err != nil {
		return "", err
	}
	base64Header := base64.RawURLEncoding.EncodeToString(headerJson)
	return base64Header, nil
}

func DecodeJWTHeader(base64Header string) (*JWTHeader, error) {
	headerJson, err := base64.RawURLEncoding.DecodeString(base64Header)
	if err != nil {
		return nil, err
	}
	var jwtHeader JWTHeader
	err = json.Unmarshal(headerJson, &jwtHeader)
	if err != nil {
		return nil, err
	}
	return &jwtHeader, nil
}

func (jwtHeader *JWTHeader) ToString() string {
	headerJson, err := json.Marshal(jwtHeader)
	if err != nil {
		return ""
	}
	return string(headerJson)

}
