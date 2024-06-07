package sqlite

import (
	"log"
	"os"
	"testing"

	"certigen/src/drivers/datastores/db"
)

type FN func(t *testing.T, store db.SqlDataStore)

func Seed(ts *testing.T, name string, fn FN) {
	store := New(Config{
		Address: os.Getenv("SQLITE_ADDRESS"),
	})
	store.Connect()
	file := os.Getenv("SQLITE_SCHEMA")
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("Cannot read schema file %s: %s", file, err)
	}
	store.ApplySchemaAndDropData(string(b))
	ts.Run(name, func(t *testing.T) {
		fn(t, store)
	})
}
