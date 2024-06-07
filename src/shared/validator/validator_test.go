package validator_test

import (
	"testing"

	"certigen/src/shared/validator"
)

type fake struct {
	Email string `valid:"email,required"`
}

func TestValidator(t *testing.T) {
	required := fake{}
	err := validator.New().Validate(required)
	if err == nil {
		t.Fatalf("Execpted err but got nothing")
	}

	invalid := fake{Email: "xxxx"}
	err = validator.New().Validate(invalid)
	if err == nil {
		t.Fatalf("Execpted err but got nothing")
	}

	valid := fake{Email: "login@mail.com"}
	err = validator.New().Validate(valid)
	if err != nil {
		t.Fatalf("Execpted ok but got error")
	}
}
