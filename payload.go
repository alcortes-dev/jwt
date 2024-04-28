package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// JWTPayload represents the payload of a JSON Web Token.
//
// The fields are optional and can contain information about the issuer,
// the subject, the name of the user, the expiration time, the not before
// time, the issued at time and the audience.
//
// The `Iss` field is a string that represents the issuer of the token.
//
// The `Sub` field is a string that represents the subject of the token.
//
// The `Name` field is a string that represents the name of the user.
//
// The `Exp` field is a integer that represents the expiration time
// of the token.
//
// The `Nbf` field is a integer that represents the not before time
// of the token.
//
// The `Iat` field is a integer that represents the issued at time
// of the token.
//
// The `Aud` field is a string that represents the audience of the token.
type JWTPayload struct {
	Iss  string `json:"iss,omitempty"`
	Sub  string `json:"sub,omitempty"`
	Name string `json:"name,omitempty"`
	Exp  int64  `json:"exp,omitempty"`
	Nbf  int64  `json:"nbf,omitempty"`
	Iat  int64  `json:"iat,omitempty"`
	Aud  string `json:"aud,omitempty"`
}

func processJWTPayload(jwtPayload *JWTPayload) (string, error) {
	payloadJson, err := json.Marshal(jwtPayload)
	if err != nil {
		return "", err
	}
	// base64Payload := make([]byte, base64.URLEncoding.EncodedLen(len(payloadJson)))
	base64Payload := base64.RawURLEncoding.EncodeToString(payloadJson)
	return base64Payload, nil
}

func decodeJWTPayload(base64Payload string) (*JWTPayload, error) {
	payloadJson, err := base64.RawURLEncoding.DecodeString(base64Payload)
	if err != nil {
		return nil, err
	}
	var jwtPayload JWTPayload
	err = json.Unmarshal(payloadJson, &jwtPayload)
	if err != nil {
		return nil, err
	}
	return &jwtPayload, nil
}

func (jwtPayload *JWTPayload) ToString() string {
	payloadJson, err := json.Marshal(jwtPayload)
	if err != nil {
		return ""
	}
	return string(payloadJson)
}
