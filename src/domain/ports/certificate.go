package ports

import (
	"context"

	"certigen/src/domain/models"
)

type CertificateRepository interface {
	Create(context.Context, models.Certificate) (models.Certificate, error)
	ReadOneByID(context.Context, string) (models.Certificate, error)
	Update(context.Context, models.Certificate) (models.Certificate, error)
}
