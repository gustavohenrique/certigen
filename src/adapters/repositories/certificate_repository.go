package repositories

import (
	"context"

	"certigen/src/adapters/converters"
	"certigen/src/adapters/dto"
	"certigen/src/domain/models"
	"certigen/src/domain/ports"
	"certigen/src/drivers/datastores/db"
)

type certificateRepository struct {
	store     db.SqlDataStore
	converter converters.CertificateConverter
}

func NewCertificateRepository(store db.SqlDataStore) ports.CertificateRepository {
	return &certificateRepository{
		store:     store,
		converter: converters.NewCertificateConverter(),
	}
}

func (r certificateRepository) Create(ctx context.Context, item models.Certificate) (models.Certificate, error) {
	q := "INSERT INTO examples (id, name) VALUES ($1, $2)"
	err := r.store.WithContext(ctx).Exec(
		q,
		item.ID,
	)
	return item, err
}

func (r certificateRepository) ReadOneByID(ctx context.Context, id string) (models.Certificate, error) {
	var item dto.PisTable
	q := "SELECT id, name FROM examples WHERE id=$1 LIMIT 1"
	err := r.store.WithContext(ctx).QueryOne(q, &item, id)
	return r.converter.FromTableToModel(item), err
}

func (r certificateRepository) Update(ctx context.Context, item models.Certificate) (models.Certificate, error) {
	q := "UPDATE examples SET name=$2 WHERE id=$1"
	err := r.store.WithContext(ctx).Exec(
		q,
		item.ID,
	)
	return item, err
}

func (r certificateRepository) Delete(ctx context.Context, item models.Certificate) (models.Certificate, error) {
	q := "DELETE FROM examples WHERE id=$1 LIMIT 1"
	err := r.store.WithContext(ctx).Exec(q, item.ID)
	return item, err
}
