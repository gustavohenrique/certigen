package jwt_test

import (
	"testing"

	"certigen/src/shared/cryptus/jwt"
)

const (
	USER_ID = "55157b04-e41d-414a-93d6-f55d43cb8f05"
)

func TestGenerateJwtExpiringInOneDay(t *testing.T) {
	j := jwt.New(jwt.Config{
		Audience:         "web",
		Issuer:           "myapp",
		ExpirationInSecs: 86400,
		Secret:           "mysecret",
	})
	token, err := j.GenerateToken(USER_ID)
	if err != nil {
		t.Fatalf("error generateToken: %s", err)
	}
	if len(token) == 0 {
		t.Fatalf("token length is zero")
	}

	id, err := j.ParseToken(token)
	if err != nil {
		t.Fatalf("error parseToken: %s", err)
	}
	if id != USER_ID {
		t.Fatalf("expected id=%s but got %s", USER_ID, id)
	}
}

/*
func TestGenerateExpiredToken(t *testing.T) {
	t.Skip()
	privateKey, err := getRsaPrivateKeyFrom(PRIVATE_KEY)
	assert.Nil(t, err)

	publicKey, err := getRsaPublicKeyFrom(PUBLIC_KEY)
	assert.Nil(t, err)

	jwt := jsonwebtoken.New(jsonwebtoken.Config{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Audience:   "web",
		Expiration: "0",
	})
	token, err := jwt.GenerateToken(USER_ID)
	assert.Nil(t, err)
	assert.True(t, len(token) > 0)

	id, err := jwt.ParseToken(token)
	assert.NotNil(t, err)
	assert.Equal(t, id, "")
}
*/
