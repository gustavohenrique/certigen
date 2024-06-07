package assert

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func Equal(t *testing.T, a interface{}, b interface{}, messages ...string) {
	if a == b {
		return
	}
	message := fmt.Sprintf("\n%v !=\n%v", a, b)
	t.Fatal(getMessage(message, messages...))
}

func NotEqual(t *testing.T, a interface{}, b interface{}, messages ...string) {
	if a != b {
		return
	}
	Equal(t, a, b, messages...)
}

func DeepEqual(t *testing.T, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		message := fmt.Sprintf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		t.Fatal(message)
		// t.FailNow()
	}
}

func True(t *testing.T, val bool) {
	if !val {
		t.Fatal("expected true but got false")
	}
}

func False(t *testing.T, val bool) {
	if val {
		t.Fatal("expected false but got true")
	}
}

func Nil(t *testing.T, a interface{}, messages ...string) {
	if isNil(a) {
		return
	}
	message := fmt.Sprintf("Expected nil, but got: %s", a)
	t.Fatal(getMessage(message, messages...))
}

func NotNil(t *testing.T, a interface{}, messages ...string) {
	if !isNil(a) {
		return
	}
	message := "Expected not nil, but got nil."
	t.Fatal(getMessage(message, messages...))
}

func Empty(t *testing.T, a interface{}, messages ...string) {
	if len(fmt.Sprintf("%s", a)) == 0 {
		return
	}
	message := "Expected empty string, but got something."
	t.Fatal(getMessage(message, messages...))
}

func NotEmpty(t *testing.T, a interface{}, messages ...string) {
	if len(fmt.Sprintf("%s", a)) > 0 {
		return
	}
	message := "Expected empty string, but got something."
	t.Fatal(getMessage(message, messages...))
}

func FileExists(t *testing.T, file string, messages ...string) {
	message := fmt.Sprintf("File %s not found", file)
	if _, err := os.Stat(file); os.IsNotExist(err) {
		t.Fatal(getMessage(message, messages...))
	}
}

func isNil(a interface{}) bool {
	if a == nil {
		return true
	}
	value := reflect.ValueOf(a)
	kind := value.Kind()
	isNilableKind := containsKind(
		[]reflect.Kind{
			reflect.Chan, reflect.Func,
			reflect.Interface, reflect.Map,
			reflect.Ptr, reflect.Slice},
		kind)

	if isNilableKind && value.IsNil() {
		return true
	}
	return false
}

func containsKind(kinds []reflect.Kind, kind reflect.Kind) bool {
	for i := 0; i < len(kinds); i++ {
		if kind == kinds[i] {
			return true
		}
	}
	return false
}

func getMessage(original string, messages ...string) string {
	var message string
	if len(messages) > 0 {
		message = strings.Join(messages, ", ")
	}
	return original + " " + message
}
