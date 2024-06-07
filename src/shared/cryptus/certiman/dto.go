package certiman

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

type Certificate struct {
	PublicKey  string
	PrivateKey string
}

type RsaKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type TlsCertificate struct {
	RsaKeyPair
	X509Certificate *x509.Certificate
}

func (s *RsaKeyPair) PrivateKeyPEM() string {
	privDER, _ := x509.MarshalPKCS8PrivateKey(s.PrivateKey)
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	privPEM := pem.EncodeToMemory(&privBlock)
	return string(privPEM)
}

type Config struct {
	id string
	expiration         time.Time
	isCa               bool
	isIntermediateCa   bool
	hosts              []string
	ocspURL            string
	organization       string
	organizationalUnit string
	country            string
	locality           string
	hasExtKeyServer    bool
	hasExtKeyClient    bool
	keySize            int
	commonName         string
	issuerName         string
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) SetID(n string) {
	c.id = n
}

func (c *Config) ID() string {
	return c.id
}

func (c *Config) SetCommonName(n string) {
	c.commonName = n
}

func (c *Config) CommonName() string {
	return c.commonName
}

func (c *Config) SetIssuerName(n string) {
	c.issuerName = n
}

func (c *Config) IssuerName() string {
	return c.issuerName
}

func (c *Config) EnableCA() {
	c.isCa = true
}

func (c *Config) DisableCA() {
	c.isCa = false
}

func (c *Config) IsCA() bool {
	return c.isCa
}

func (c *Config) EnableIntermediateCA() {
	c.isIntermediateCa = true
}

func (c *Config) DisableIntermediateCA() {
	c.isIntermediateCa = false
}

func (c *Config) IsIntermediateCA() bool {
	return c.isIntermediateCa
}

func (c *Config) SetKeySize(i int) {
	c.keySize = i
}

func (c *Config) KeySize() int {
	if c.keySize != 2048 && c.keySize != 4096 {
		return 4096
	}
	return c.keySize
}

func (c *Config) SetExpirationDate(d time.Time) {
	c.expiration = d
}

func (c *Config) ExpiresAt() time.Time {
	now := time.Now()
	if c.expiration.Before(now) {
		return now.AddDate(0, 12, 0)
	}
	return c.expiration
}

func (c *Config) SetOrganization(organization string) {
	organization = strings.TrimSpace(organization)
	if len(organization) == 0 {
		c.organization = "Unknown Org"
	}
	c.organization = organization
}

func (c *Config) Organization() string {
	return c.organization
}

func (c *Config) SetOrganizationalUnit(ou string) {
	ou = strings.TrimSpace(ou)
	c.organizationalUnit = ou
}

func (c *Config) OrganizationalUnit() string {
	return c.organizationalUnit
}

func (c *Config) SetCountry(country string) {
	country = strings.ToUpper(strings.TrimSpace(country))
	if len(country) != 2 {
		c.country = "??"
	}
	c.country = country
}

func (c *Config) Country() string {
	return c.country
}

func (c *Config) SetLocality(locality string) {
	locality = strings.TrimSpace(locality)
	c.locality = locality
}

func (c *Config) Locality() string {
	return c.locality
}

func (c *Config) SetHosts(hosts []string) {
	var trim []string
	for _, h := range hosts {
		trim = append(trim, strings.TrimSpace(h))
	}
	c.hosts = trim
}

func (c *Config) Hosts() []string {
	return c.hosts
}

func (c *Config) SetOcspURL(url string) {
	c.ocspURL = strings.TrimSpace(url)
}

func (c *Config) OcspURL() string {
	return c.ocspURL
}

func (c *Config) EnableExtKeyServer() {
	c.hasExtKeyServer = true
}

func (c *Config) HasExtKeyServer() bool {
	return c.hasExtKeyServer
}
