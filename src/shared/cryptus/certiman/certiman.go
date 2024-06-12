package certiman

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"time"
)

var certificateTemplateNilErr = fmt.Errorf("certificate template is nil")

type certificateManager struct {
	certificateTemplate *CertificateTemplate
}

func New() Certiman {
	return &certificateManager{}
}

func (s *certificateManager) With(template *CertificateTemplate) Certiman {
	s.certificateTemplate = template
	return s
}

func (s *certificateManager) CreateRootCA() (Certificate, error) {
	var result Certificate
	var certificateTemplate = s.certificateTemplate
	if certificateTemplate == nil {
		return result, certificateTemplateNilErr
	}
	keyPair, err := s.generateRsaKeyPair(certificateTemplate)
	if err != nil {
		return result, err
	}
	certificateTemplate.EnableCA()
	certificateTemplate.EnableExtKeyServer()
	cert := s.generateX509Template(certificateTemplate)
	return s.buildPEM(cert, cert, keyPair.PrivateKey, keyPair)
}

func (s *certificateManager) CreateIntermediateCA(ca Certificate) (Certificate, error) {
	var certificateTemplate = s.certificateTemplate
	if certificateTemplate == nil {
		return Certificate{}, certificateTemplateNilErr
	}
	certificateTemplate.DisableCA()
	certificateTemplate.EnableIntermediateCA()
	certificateTemplate.EnableExtKeyServer()
	cert := s.generateX509Template(certificateTemplate)
	signed, err := s.createSignedCertificate(cert, ca)
	return signed, err

}

func (s *certificateManager) CreateServerCert(ca Certificate) (Certificate, error) {
	var certificateTemplate = s.certificateTemplate
	if certificateTemplate == nil {
		return Certificate{}, certificateTemplateNilErr
	}
	certificateTemplate.EnableExtKeyServer()
	certificateTemplate.DisableCA()
	certificateTemplate.DisableIntermediateCA()
	cert := s.generateX509Template(certificateTemplate)
	return s.createSignedCertificate(cert, ca)
}

func (s *certificateManager) CreateClientCert(ca Certificate) (Certificate, error) {
	var certificateTemplate = s.certificateTemplate
	if certificateTemplate == nil {
		return Certificate{}, certificateTemplateNilErr
	}
	certificateTemplate.DisableCA()
	certificateTemplate.DisableIntermediateCA()
	cert := s.generateX509Template(certificateTemplate)
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
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		priv, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	}
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
	var certificateTemplate = s.certificateTemplate
	if certificateTemplate == nil {
		return result, certificateTemplateNilErr
	}
	keyPair, err := s.generateRsaKeyPair(certificateTemplate)
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

func (s *certificateManager) configureASN1(cert *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return cert, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return cert, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	cert.SubjectKeyId = skid[:]
	return cert, nil
}

func (s *certificateManager) buildPEM(template, parent *x509.Certificate, priv *rsa.PrivateKey, keyPair RsaKeyPair) (Certificate, error) {
	var result Certificate
	template, err := s.configureASN1(template, keyPair.PublicKey)
	if err != nil {
		return result, err
	}
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

func (s *certificateManager) generateRsaKeyPair(certificateTemplate *CertificateTemplate) (RsaKeyPair, error) {
	var result RsaKeyPair
	priv, err := s.generateKey(certificateTemplate.KeySize())
	if err != nil {
		return result, err
	}
	// pub := priv.(crypto.Signer).Public()
	result.PrivateKey = priv
	result.PublicKey = &priv.PublicKey
	return result, nil
}

func (s *certificateManager) generateX509Template(certificateTemplate *CertificateTemplate) *x509.Certificate {
	serial := certificateTemplate.SerialNumber()
	cert := &x509.Certificate{
		SerialNumber: &serial,
		Issuer: pkix.Name{
			CommonName: certificateTemplate.IssuerName(),
		},
		PermittedURIDomains: certificateTemplate.PermittedUriDomains(),
		Subject: pkix.Name{
			SerialNumber:       certificateTemplate.ID(),
			CommonName:         certificateTemplate.CommonName(),
			Organization:       certificateTemplate.Organizations(),
			Country:            certificateTemplate.Countries(),
			Locality:           certificateTemplate.Localities(),
			OrganizationalUnit: certificateTemplate.OrganizationalUnits(),
		},
		NotBefore:          time.Now(),
		NotAfter:           certificateTemplate.ExpiresAt(),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		Version:            3,
	}
	for _, h := range certificateTemplate.Hosts() {
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

	if certificateTemplate.IsCA() {
		cert.IsCA = true
		cert.MaxPathLen = 1
		cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		return cert
	}

	if certificateTemplate.IsIntermediateCA() {
		cert.IsCA = true
		cert.MaxPathLen = 0
		cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		return cert
	}

	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	ocspURL := certificateTemplate.OcspURL()
	if uriName, err := url.Parse(ocspURL); err == nil && uriName.Scheme != "" && uriName.Host != "" {
		cert.OCSPServer = []string{ocspURL}
	}

	cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	if certificateTemplate.HasExtKeyServer() {
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

func RandomSerialNumber() big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return *big.NewInt(0)
	}
	return *serialNumber
}

func (s *certificateManager) generateKey(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}
