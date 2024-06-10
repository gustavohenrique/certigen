package ports

import (
	"context"
	"math/big"

	"certigen/src/domain/models"
)

type CertificateRepository interface {
	Create(context.Context, models.Certificate) (models.Certificate, error)
	ReadOneByID(context.Context, string) (models.Certificate, error)
	ReadOneBySerial(context.Context, big.Int) (models.Certificate, error)
	Revoke(context.Context, models.Certificate) error
	Delete(context.Context, models.Certificate) error
}
