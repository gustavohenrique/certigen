package ports

type RepositoryContainer interface {
	CertificateRepository() CertificateRepository
}
