package repositories_test

import (
	"context"
	"fmt"
	"testing"

	"certigen/src/adapters/dto"
	"certigen/src/adapters/repositories"
	"certigen/src/domain/models"
	"certigen/src/drivers/datastores/db"
	"certigen/src/drivers/datastores/sqlite"
	"certigen/src/shared/testify/assert"
)

func TestPisRepository(ts *testing.T) {
	ctx := context.Background()

	sqlite.Seed(ts, "", func(t *testing.T, store db.SqlDataStore) {
		repo := repositories.NewCertificateRepository(store)
		item := models.Certificate{}
		item.ID = "teste"
		_, err := repo.Create(ctx, item)
		assert.Nil(t, err, "Erro no create", fmt.Sprintf("%s", err))

		var found dto.PisTable
		err = store.WithContext(ctx).QueryOne("select id, name from examples", &found)
		assert.Nil(t, err)
	})
}
