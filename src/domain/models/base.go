package models

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type Certificate struct {
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	X509Certificate *x509.Certificate
	ID              string
	PublicKeyPEM    string
	PrivateKeyPEM   string
	SerialNumber    big.Int
	CreatedAt       *time.Time
	RevokedAt       *time.Time
	RevokedReason   int
	Organization    string
	Teams           []string
	Projects        []string
	Hosts           []string
	Environments    []string
}

func LoadCertificate(pubKey, privKey string) (Certificate, error) {
	pubPEM, err := os.ReadFile(pubKey)
	if err != nil {
		return Certificate{}, err
	}
	privPEM, err := os.ReadFile(privKey)
	if err != nil {
		return Certificate{}, err
	}
	return NewCertificate(string(pubPEM), string(privPEM))
}

func NewCertificate(pubPEM, privPEM string) (Certificate, error) {
	var result Certificate
	certBlock, _ := pem.Decode([]byte(pubPEM))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return result, fmt.Errorf("cannot parse pub key: %s", err)
	}

	privBlock, _ := pem.Decode([]byte(privPEM))
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return result, fmt.Errorf("cannot parse priv key: %s", err)
	}

	result.X509Certificate = cert
	result.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	result.PrivateKey = priv.(*rsa.PrivateKey)
	return result, nil
}

func (c Certificate) Revoked() bool {
	return c.RevokedAt != nil
}

func (c Certificate) X509() *x509.Certificate {
	certBlock, _ := pem.Decode([]byte(c.PublicKeyPEM))
	pubDER, _ := x509.ParseCertificate(certBlock.Bytes)
	return pubDER
}

func (c Certificate) MarshalPKCS8PrivateKey() []byte {
	privDER, _ := x509.MarshalPKCS8PrivateKey(c.PrivateKeyPEM)
	return privDER
}

type RevokedCertificate struct {
	Status           int
	SerialNumber     string
	RevocationReason int
	ThisUpdate       time.Time
	NextUpdate       time.Time
}
