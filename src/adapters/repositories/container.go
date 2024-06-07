package repositories

import (
	"certigen/src/domain/ports"
	"certigen/src/drivers/datastores"
)

type container struct {
	certificateRepository ports.CertificateRepository
}

func NewRepositoryContainer(ds datastores.DataStore) ports.RepositoryContainer {
	return container{
		certificateRepository: NewCertificateRepository(ds.Sqlite()),
	}
}

func (c container) CertificateRepository() ports.CertificateRepository {
	return c.certificateRepository
}
