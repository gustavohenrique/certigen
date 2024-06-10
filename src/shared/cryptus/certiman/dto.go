package certiman

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
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
	serialNumber        big.Int
	id                  string
	expiration          time.Time
	isCa                bool
	isIntermediateCa    bool
	hosts               []string
	permittedUriDomains               []string
	ocspURL             string
	organizations       []string
	organizationalUnits []string
	countries           []string
	localities          []string
	hasExtKeyServer     bool
	hasExtKeyClient     bool
	keySize             int
	commonName          string
	issuerName          string
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

func (c *Config) SetSerialNumber(n big.Int) {
	c.serialNumber = n
}

func (c *Config) SerialNumber() big.Int {
	if c.serialNumber.Cmp(big.NewInt(0)) == 0 {
		return RandomSerialNumber()
	}
	return c.serialNumber
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

func (c *Config) SetOrganizations(organizations []string) {
	c.organizations = organizations
}

func (c *Config) AddOrganization(organization string) {
	organization = strings.TrimSpace(organization)
	if len(organization) == 0 {
		organization = "Unknown Org"
	}
	c.organizations = append(c.organizations, organization)
}

func (c *Config) Organizations() []string {
	return c.organizations
}

func (c *Config) SetOrganizationalUnits(units []string) {
	c.organizationalUnits = units
}

func (c *Config) AddOrganizationalUnit(ou string) {
	ou = strings.TrimSpace(ou)
	c.organizationalUnits = append(c.organizationalUnits, ou)
}

func (c *Config) OrganizationalUnits() []string {
	return c.organizationalUnits
}

func (c *Config) SetCountries(countries []string) {
	c.countries = countries
}

func (c *Config) AddCountry(country string) {
	country = strings.ToUpper(strings.TrimSpace(country))
	if len(country) != 2 {
		country = "Brazil"
	}
	c.countries = append(c.countries, country)
}

func (c *Config) Countries() []string {
	return c.countries
}

func (c *Config) SetLocalities(locals []string) {
	c.localities = locals
}

func (c *Config) AddLocality(locality string) {
	locality = strings.TrimSpace(locality)
	c.localities = append(c.localities, locality)
}

func (c *Config) Localities() []string {
	return c.localities
}

func (c *Config) SetHosts(hosts []string) {
	c.hosts = hosts
}

func (c *Config) AddHost(host string) {
	c.hosts = append(c.hosts, strings.TrimSpace(host))
}

func (c *Config) Hosts() []string {
	return c.hosts
}

func (c *Config) SetPermittedUriDomains(permittedUriDomains []string) {
	c.permittedUriDomains = permittedUriDomains
}

func (c *Config) AddPermittedUriDomain(uri string) {
	c.permittedUriDomains = append(c.permittedUriDomains, strings.TrimSpace(uri))
}

func (c *Config) PermittedUriDomains() []string {
	return c.permittedUriDomains
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
