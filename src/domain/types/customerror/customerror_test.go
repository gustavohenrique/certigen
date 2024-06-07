package customerror_test

import (
	"fmt"
	"net/http"
	"testing"

	"certigen/src/domain/types/customerror"
)

func TestCustomError(t *testing.T) {
	assertEqual(t, customerror.StatusCodeFrom(getErr()), http.StatusInternalServerError)
	assertEqual(t, customerror.StatusCodeFrom(fmt.Errorf("duplicate key")), http.StatusConflict)

	var err error
	err = customerror.Wrap(getErr())
	assertEqual(t, customerror.StatusCodeFrom(err), http.StatusInternalServerError)

	err = customerror.NotFound(getErr(), "")
	assertEqual(t, customerror.StatusCodeFrom(err), http.StatusNotFound)

	err = customerror.InvalidInput(getErr(), "")
	assertEqual(t, customerror.StatusCodeFrom(err), http.StatusBadRequest)

	err = customerror.Denied(getErr(), "")
	assertEqual(t, customerror.StatusCodeFrom(err), http.StatusForbidden)

	err = customerror.Denied(nil, "")
	assertEqual(t, customerror.StatusCodeFrom(err), http.StatusForbidden)
}

func getErr() error {
	return fmt.Errorf("some error")
}

func assertEqual(t *testing.T, got, expected interface{}) {
	if got != expected {
		t.Fatalf("expected=%v got=%v", expected, got)
	}
}
