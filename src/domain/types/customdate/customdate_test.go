package customdate_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"certigen/src/domain/types/customdate"
)

const xmas = "2023-12-25"

func TestCustomDate(t *testing.T) {
	type SomeStruct struct {
		CreatedAt customdate.CustomDate `json:"created_at"`
	}

	// TryParse
	dates := []string{
		"2024-04",
		"2023-11-21",
		"10/03/2022",
		"2020-12-31T00:00:00Z",
		"2020-12-31T00:00:00",
		"2020-12-31T00:00:00-03:00",
	}
	for _, dateStr := range dates {
		dt, err := customdate.TryParse(dateStr)
		fmt.Println(dt)
		assertEqual(t, err, nil)
	}

	// Format
	newYear := customdate.Parse("2023-12-31T12:13:14-03:00")
	assertEqual(t, newYear.ToYearMonthDayFormat(), "2023-12-31")
	assertEqual(t, newYear.ToDayMonthYearSlashFormat(), "31/12/2023")
	assertEqual(t, newYear.ToISO8601Format(), "2023-12-31T12:13:14")
	assertEqual(t, newYear.ToUTC(), "2023-12-31T12:13:14Z")

	// Marshal
	dt := customdate.Parse(xmas)
	ss := SomeStruct{CreatedAt: dt}
	b, _ := json.Marshal(ss)
	assertEqual(t, string(b), `{"created_at":"2023-12-25T00:00:00Z"}`)

	// Marshal returning null
	type AnotherStruct struct {
		CreatedAt customdate.CustomDate `json:"created_at"`
	}

	var emptyDate customdate.CustomDate
	anotherStruct := AnotherStruct{CreatedAt: emptyDate}
	b, _ = json.Marshal(anotherStruct)
	assertEqual(t, string(b), `{"created_at":null}`)

	// Unmarshal
	var someStruct SomeStruct
	json.Unmarshal([]byte(`{"created_at":"2023-12-25T00:00:00"}`), &someStruct)
	day := someStruct.CreatedAt.Day()
	month := someStruct.CreatedAt.Month()
	year := someStruct.CreatedAt.Year()
	if day != 25 || month != 12 || year != 2023 {
		t.Fatalf("Unmarshal error. Got %d-%d-%d", year, month, day)
	}
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		return
	}
	message := fmt.Sprintf("\n%v !=\n%v", a, b)
	t.Fatal(message)
}
