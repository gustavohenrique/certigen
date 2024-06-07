package stringfy

import (
	"encoding/json"
	"sort"
	"strings"
)

func HasEmpty(s ...string) bool {
	for _, i := range s {
		if Trim(i) == "" {
			return true
		}
	}
	return false
}

func Trim(s string) string {
	return strings.TrimSpace(s)
}

func SliceContains(s []string, term string) bool {
	sort.Strings(s)
	i := sort.SearchStrings(s, term)
	return i < len(s) && s[i] == term
}

func PrettyJSON(i interface{}) string {
	res, _ := json.MarshalIndent(i, "", "    ")
	return string(res)
}

func FromJSON(s string, i interface{}) error {
	return json.Unmarshal([]byte(s), i)
}

func ToJSON(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		return ""
	}
	return string(b)
}
