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

type CertificateTemplate struct {
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

func NewTemplate() *CertificateTemplate {
	return &CertificateTemplate{}
}

func (c *CertificateTemplate) SetID(n string) {
	c.id = n
}

func (c *CertificateTemplate) ID() string {
	return c.id
}

func (c *CertificateTemplate) SetSerialNumber(n big.Int) {
	c.serialNumber = n
}

func (c *CertificateTemplate) SerialNumber() big.Int {
	if c.serialNumber.Cmp(big.NewInt(0)) == 0 {
		return RandomSerialNumber()
	}
	return c.serialNumber
}

func (c *CertificateTemplate) SetCommonName(n string) {
	c.commonName = n
}

func (c *CertificateTemplate) CommonName() string {
	return c.commonName
}

func (c *CertificateTemplate) SetIssuerName(n string) {
	c.issuerName = n
}

func (c *CertificateTemplate) IssuerName() string {
	return c.issuerName
}

func (c *CertificateTemplate) EnableCA() {
	c.isCa = true
}

func (c *CertificateTemplate) DisableCA() {
	c.isCa = false
}

func (c *CertificateTemplate) IsCA() bool {
	return c.isCa
}

func (c *CertificateTemplate) EnableIntermediateCA() {
	c.isIntermediateCa = true
}

func (c *CertificateTemplate) DisableIntermediateCA() {
	c.isIntermediateCa = false
}

func (c *CertificateTemplate) IsIntermediateCA() bool {
	return c.isIntermediateCa
}

func (c *CertificateTemplate) SetKeySize(i int) {
	c.keySize = i
}

func (c *CertificateTemplate) KeySize() int {
	if c.keySize != 2048 && c.keySize != 4096 {
		return 4096
	}
	return c.keySize
}

func (c *CertificateTemplate) SetExpirationDate(d time.Time) {
	c.expiration = d
}

func (c *CertificateTemplate) ExpiresAt() time.Time {
	now := time.Now()
	if c.expiration.Before(now) {
		return now.AddDate(0, 12, 0)
	}
	return c.expiration
}

func (c *CertificateTemplate) SetOrganizations(organizations []string) {
	c.organizations = organizations
}

func (c *CertificateTemplate) AddOrganization(organization string) {
	organization = strings.TrimSpace(organization)
	if len(organization) == 0 {
		organization = "Unknown Org"
	}
	c.organizations = append(c.organizations, organization)
}

func (c *CertificateTemplate) Organizations() []string {
	return c.organizations
}

func (c *CertificateTemplate) SetOrganizationalUnits(units []string) {
	c.organizationalUnits = units
}

func (c *CertificateTemplate) AddOrganizationalUnit(ou string) {
	ou = strings.TrimSpace(ou)
	c.organizationalUnits = append(c.organizationalUnits, ou)
}

func (c *CertificateTemplate) OrganizationalUnits() []string {
	return c.organizationalUnits
}

func (c *CertificateTemplate) SetCountries(countries []string) {
	c.countries = countries
}

func (c *CertificateTemplate) AddCountry(country string) {
	country = strings.ToUpper(strings.TrimSpace(country))
	if len(country) != 2 {
		country = "Brazil"
	}
	c.countries = append(c.countries, country)
}

func (c *CertificateTemplate) Countries() []string {
	return c.countries
}

func (c *CertificateTemplate) SetLocalities(locals []string) {
	c.localities = locals
}

func (c *CertificateTemplate) AddLocality(locality string) {
	locality = strings.TrimSpace(locality)
	c.localities = append(c.localities, locality)
}

func (c *CertificateTemplate) Localities() []string {
	return c.localities
}

func (c *CertificateTemplate) SetHosts(hosts []string) {
	c.hosts = hosts
}

func (c *CertificateTemplate) AddHost(host string) {
	c.hosts = append(c.hosts, strings.TrimSpace(host))
}

func (c *CertificateTemplate) Hosts() []string {
	return c.hosts
}

func (c *CertificateTemplate) SetPermittedUriDomains(permittedUriDomains []string) {
	c.permittedUriDomains = permittedUriDomains
}

func (c *CertificateTemplate) AddPermittedUriDomain(uri string) {
	c.permittedUriDomains = append(c.permittedUriDomains, strings.TrimSpace(uri))
}

func (c *CertificateTemplate) PermittedUriDomains() []string {
	return c.permittedUriDomains
}

func (c *CertificateTemplate) SetOcspURL(url string) {
	c.ocspURL = strings.TrimSpace(url)
}

func (c *CertificateTemplate) OcspURL() string {
	return c.ocspURL
}

func (c *CertificateTemplate) EnableExtKeyServer() {
	c.hasExtKeyServer = true
}

func (c *CertificateTemplate) HasExtKeyServer() bool {
	return c.hasExtKeyServer
}
