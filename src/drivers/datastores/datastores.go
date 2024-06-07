package datastores

import (
	"certigen/src/shared/configurator"

	"certigen/src/drivers/datastores/db"
	"certigen/src/drivers/datastores/sqlite"
)

type dataStoreContainer struct {
	config *configurator.AppConfig
	sqlite db.SqlDataStore
}

func New() DataStore {
	config := configurator.GetAppConfig()
	datastores := &dataStoreContainer{config: config}
	return datastores
}

func (d *dataStoreContainer) Sqlite() db.SqlDataStore {
	if d.sqlite == nil {
		d.sqlite = sqlite.New(sqlite.Config{
			Address: d.config.Sqlite.Address,
		})
	}
	return d.sqlite
}
