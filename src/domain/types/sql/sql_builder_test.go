package sql_test

import (
	"fmt"
	"testing"

	"certigen/src/domain/types/sql"
)

func TestSearchBuilder(t *testing.T) {
	builder := sql.NewPostgresSqlBuilder()
	builder.Where(
		builder.AndWhere("id", "=", "123"),
		builder.AndWhere("created_at", ">=", "current_timestramp"),
		builder.OrWhere("email", "like", "%@gmail"),
	).OrderBy(
		builder.AscOrder("id"),
		builder.DescOrder("created_at"),
	).Limit(1, 10)

	where := builder.BuildWhereQuery()
	assertEqual(t, where, " WHERE 1=1 AND id = $1 AND created_at >= $2 OR email like $3")

	totalPlaceholders := len(builder.WhereValues())
	assertEqual(t, totalPlaceholders, 3)

	pagination := builder.BuildPaginationQuery()
	assertEqual(t, pagination, " LIMIT 10 OFFSET 0")

	orderBy := builder.BuildOrderByQuery()
	assertEqual(t, orderBy, " ORDER BY id ASC, created_at DESC")

	query := builder.Query()
	assertEqual(t, query, " WHERE 1=1 AND id = $1 AND created_at >= $2 OR email like $3 ORDER BY id ASC, created_at DESC LIMIT 10 OFFSET 0")
}

func assertEqual(t *testing.T, got, expected interface{}) {
	if got != expected {
		t.Fatalf(fmt.Sprintf("expected=%s got=%s", expected, got))
	}
}
