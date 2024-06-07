package cryptus

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func AesGcmEncrypt(secret, encodedUserKey string) (string, error) {
	decoded, _ := base64.StdEncoding.DecodeString(encodedUserKey)
	splited := strings.Split(string(decoded), "$")
	if len(splited) >= 5 {
		rand.NewSource(time.Now().UnixNano())
		nonce := make([]byte, 12)
		crand.Read(nonce)
		key := splited[5][0:32]
		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			return "", fmt.Errorf("cannot create cipher.")
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("cannot allocate cipher block.")
		}
		encrypted := aesgcm.Seal(nil, nonce, []byte(secret), nil)
		encodedSecret := base64.StdEncoding.EncodeToString(encrypted)
		encodedNonce := base64.StdEncoding.EncodeToString(nonce)
		return encodedSecret + encodedNonce, nil
	}
	return "", fmt.Errorf("the decoded user key is not in argon2iv format.")
}

func ToBase64(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func FromBase64(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}

func IsBase64(str string) bool {
	_, err := FromBase64(str)
	return err == nil
}
