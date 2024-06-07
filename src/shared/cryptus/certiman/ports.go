package certiman

type Certiman interface {
	With(config *Config) Certiman
	CreateRootCA() (Certificate, error)
	CreateIntermediateCA(ca Certificate) (Certificate, error)
	CreateServerCert(ca Certificate) (Certificate, error)
	CreateClientCert(ca Certificate) (Certificate, error)
	Parse(certificate Certificate) (TlsCertificate, error)
}
