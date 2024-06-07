package certiman

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"time"
)

var configNilErr = fmt.Errorf("config is nil")

type certificateManager struct {
	config *Config
}

func New() Certiman {
	return &certificateManager{}
}

func (s *certificateManager) With(config *Config) Certiman {
	s.config = config
	return s
}

func (s *certificateManager) CreateRootCA() (Certificate, error) {
	var result Certificate
	var config = s.config
	if config == nil {
		return result, configNilErr
	}
	keyPair, err := s.generateRsaKeyPair(config)
	if err != nil {
		return result, err
	}
	config.EnableCA()
	config.EnableExtKeyServer()
	cert := s.generateX509Template(config)
	return s.buildPEM(cert, cert, keyPair.PrivateKey, keyPair)
}

func (s *certificateManager) CreateIntermediateCA(ca Certificate) (Certificate, error) {
	var config = s.config
	if config == nil {
		return Certificate{}, configNilErr
	}
	config.DisableCA()
	config.EnableIntermediateCA()
	config.EnableExtKeyServer()
	cert := s.generateX509Template(config)
	signed, err := s.createSignedCertificate(cert, ca)
	return signed, err

}

func (s *certificateManager) CreateServerCert(ca Certificate) (Certificate, error) {
	var config = s.config
	if config == nil {
		return Certificate{}, configNilErr
	}
	config.EnableExtKeyServer()
	config.DisableCA()
	config.DisableIntermediateCA()
	cert := s.generateX509Template(config)
	return s.createSignedCertificate(cert, ca)
}

func (s *certificateManager) CreateClientCert(ca Certificate) (Certificate, error) {
	var config = s.config
	if config == nil {
		return Certificate{}, configNilErr
	}
	config.DisableCA()
	config.DisableIntermediateCA()
	cert := s.generateX509Template(config)
	return s.createSignedCertificate(cert, ca)
}

func (s *certificateManager) Parse(certificate Certificate) (TlsCertificate, error) {
	var result TlsCertificate
	certBlock, _ := pem.Decode([]byte(certificate.PublicKey))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return result, fmt.Errorf("cannot parse pub key: %s", err)
	}

	privBlock, _ := pem.Decode([]byte(certificate.PrivateKey))
	// priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return result, fmt.Errorf("cannot parse priv key: %s", err)
	}

	result.X509Certificate = cert
	result.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	result.PrivateKey = priv.(*rsa.PrivateKey)
	return result, nil
}

func (s *certificateManager) createSignedCertificate(cert *x509.Certificate, parentCert Certificate) (Certificate, error) {
	var result Certificate
	var config = s.config
	if config == nil {
		return result, configNilErr
	}
	keyPair, err := s.generateRsaKeyPair(config)
	if err != nil {
		return result, err
	}

	parent, err := s.Parse(parentCert)
	if err != nil || parent.X509Certificate == nil {
		return result, err
	}
	parentCommonName := parent.X509Certificate.Subject.CommonName
	cert.Issuer.CommonName = parentCommonName
	certificate, err := s.buildPEM(cert, parent.X509Certificate, parent.PrivateKey, keyPair)
	return certificate, err
}

func (s *certificateManager) buildPEM(template, parent *x509.Certificate, priv *rsa.PrivateKey, keyPair RsaKeyPair) (Certificate, error) {
	var result Certificate
	pubDER, err := x509.CreateCertificate(rand.Reader, template, parent, keyPair.PublicKey, priv)
	if err != nil {
		return result, fmt.Errorf("cannot create certificate: %s", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pubDER,
	})

	privDER, _ := x509.MarshalPKCS8PrivateKey(keyPair.PrivateKey)
	// privDER := x509.MarshalPKCS1PrivateKey(priv)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	result.PrivateKey = string(privKeyPEM)
	result.PublicKey = string(pubKeyPEM)
	return result, nil
}

func (s *certificateManager) generateRsaKeyPair(config *Config) (RsaKeyPair, error) {
	var result RsaKeyPair
	priv, err := s.generateKey(config.KeySize())
	if err != nil {
		return result, err
	}
	// pub := priv.(crypto.Signer).Public()
	result.PrivateKey = priv
	result.PublicKey = &priv.PublicKey
	return result, nil
}

func (s *certificateManager) generateX509Template(config *Config) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: s.randomSerialNumber(),
		Issuer: pkix.Name{
			CommonName: config.IssuerName(),
		},
		PermittedURIDomains: config.Hosts(),
		Subject: pkix.Name{
			SerialNumber:       config.ID(),
			CommonName:         config.CommonName(),
			Organization:       []string{config.Organization()},
			Country:            []string{config.Country()},
			Locality:           []string{config.Locality()},
			OrganizationalUnit: []string{config.OrganizationalUnit()},
		},
		NotBefore:          time.Now(),
		NotAfter:           config.ExpiresAt(),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Version:            3,
	}
	for _, h := range config.Hosts() {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			cert.EmailAddresses = append(cert.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			cert.URIs = append(cert.URIs, uriName)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}

	cert.BasicConstraintsValid = true

	if config.IsCA() {
		cert.IsCA = true
		cert.MaxPathLen = 1
		cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		return cert
	}

	if config.IsIntermediateCA() {
		cert.IsCA = true
		cert.MaxPathLen = 0
		cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		return cert
	}

	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	ocspURL := config.OcspURL()
	if uriName, err := url.Parse(ocspURL); err == nil && uriName.Scheme != "" && uriName.Host != "" {
		cert.OCSPServer = []string{ocspURL}
	}

	cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	if config.HasExtKeyServer() {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	// if len(cert.IPAddresses) > 0 || len(cert.DNSNames) > 0 || len(cert.URIs) > 0 {
	//     cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	// }
	if len(cert.EmailAddresses) > 0 {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}
	return cert
}

func (s *certificateManager) randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}

func (s *certificateManager) generateKey(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}
