package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	// PrivateKey       *rsa.PrivateKey
	// PublicKey        *rsa.PublicKey
	Secret           string
	Audience         string
	Issuer           string
	ExpirationInSecs int
}

type customJwt struct {
	config Config
}

func New(config Config) Jwt {
	if config.Audience == "" {
		config.Audience = "web"
	}
	if config.Issuer == "" {
		config.Issuer = "webapp"
	}
	if strings.TrimSpace(config.Secret) == "" {
		config.Secret = "some-strong-secret"
	}
	return &customJwt{config}
}

func (j *customJwt) GenerateToken(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("cannot generate token for empty string")
	}
	expiration := time.Second * time.Duration(j.config.ExpirationInSecs)
	claims := jwt.RegisteredClaims{
		ID:        id,
		Issuer:    j.config.Issuer,
		Audience:  []string{j.config.Audience},
		Subject:   id,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	key := j.config.Secret
	// if strings.TrimSpace(key) == "" {
	// return t.SignedString(j.config.PrivateKey)
	// }
	return t.SignedString([]byte(key))
}

func (j *customJwt) ParseToken(tokenString string) (string, error) {
	t, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		key := j.config.Secret
		// if strings.TrimSpace(key) == "" {
		//     return j.config.PublicKey, nil
		// }
		return []byte(key), nil
	})
	switch {
	case t != nil && t.Valid:
		claims, ok := t.Claims.(*jwt.RegisteredClaims)
		if !ok {
			return "", fmt.Errorf("invalid token")
		}
		return claims.ID, nil
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "", fmt.Errorf("token malformed signature")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "", fmt.Errorf("invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		return "", fmt.Errorf("token expired")
	default:
		return "", fmt.Errorf("couldn't handle this token: %s", err)
	}
}
