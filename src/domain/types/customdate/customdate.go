package customdate

import (
	"fmt"
	"time"
)

const (
	layoutYearMonth  = "2006-01"
	layoutUsDate     = "2006-01-02"
	layoutBrDate     = "02/01/2006"
	layoutBrDateTime = "02/01/2006 15:04:05"
	layoutISO8601    = "2006-01-02T15:04:05"
	layoutUTC        = "2006-01-02T15:04:05Z"
	layoutWithTZ     = "2006-01-02T15:04:05-07:00"
)

const defaultLayoutForJSON = layoutUTC

var layouts = [7]string{
	layoutYearMonth,
	layoutUsDate,
	layoutBrDate,
	layoutBrDateTime,
	layoutISO8601,
	layoutUTC,
	layoutWithTZ,
}

type CustomDate struct {
	time.Time
}

func Parse(s string) CustomDate {
	dt, _ := TryParse(s)
	return dt
}

func TryParse(s string) (CustomDate, error) {
	for _, layout := range layouts {
		dt, err := time.Parse(layout, s)
		if err == nil {
			return CustomDate{Time: dt}, nil
		}
	}
	return CustomDate{}, fmt.Errorf("invalid format for %s", s)
}

func (c *CustomDate) ToYearMonthFormat() string {
	return c.Format(layoutYearMonth)
}

func (c *CustomDate) ToISO8601Format() string {
	return c.Format(layoutISO8601)
}

func (c *CustomDate) ToDayMonthYearSlashFormat() string {
	return c.Format(layoutBrDate)
}

func (c *CustomDate) ToYearMonthDayFormat() string {
	return c.Format(layoutUsDate)
}

func (c *CustomDate) ToUTC() string {
	return c.Format(layoutUTC)
}

func (c *CustomDate) UnmarshalJSON(data []byte) error {
	for _, layout := range layouts {
		dt, err := time.Parse(`"`+layout+`"`, string(data))
		if err == nil {
			c.Time = dt
			return nil
		}
	}
	return fmt.Errorf("invalid format for %s", string(data))
}

func (c CustomDate) MarshalJSON() ([]byte, error) {
	if c.IsZero() {
		return []byte(`null`), nil
	}
	return []byte(fmt.Sprintf(`"%s"`, c.Time.Format(defaultLayoutForJSON))), nil
}
