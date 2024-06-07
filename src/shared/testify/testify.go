package testify

import (
	"encoding/json"
	"testing"

	"go.uber.org/mock/gomock"
)

func It(ts *testing.T, name string, fn func(t *testing.T)) {
	ts.Run(name, fn)
}

func FormatMock(y interface{}) gomock.Matcher {
	x := gomock.WantFormatter(
		gomock.StringerFunc(func() string {
			z := structToMap(y)
			b, _ := json.Marshal(z)
			return string(b)
		}),
		gomock.Eq(y),
	)
	return gomock.GotFormatterAdapter(
		gomock.GotFormatterFunc(func(i any) string {
			b, _ := json.Marshal(i)
			return string(b)
		}),
		x,
	)
}

func structToMap(obj interface{}) map[string]interface{} {
	var result map[string]interface{}
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return nil
	}
	return result
}
