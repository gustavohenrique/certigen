package datastores

import (
	"certigen/src/drivers/datastores/db"
)

type DataStore interface {
	Sqlite() db.SqlDataStore
}
