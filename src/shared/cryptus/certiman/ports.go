package certiman

type Certiman interface {
	With(template *CertificateTemplate) Certiman
	WithKeyPair(pubKey, privKey string) Certiman
	CreateRootCA() (Certificate, error)
	CreateIntermediateCA() (Certificate, error)
	CreateServerCert() (Certificate, error)
	CreateClientCert() (Certificate, error)
	Parse(certificate Certificate) (TlsCertificate, error)
}
