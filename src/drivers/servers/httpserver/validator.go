package httpserver

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"certigen/src/shared/validator"
)

type customValidator struct {
	validator validator.Validator
}

func (cv *customValidator) Validate(i interface{}) error {
	if err := cv.validator.Validate(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func (s *httpServer) UseRequestValidator() {
	s.rawServer.Validator = &customValidator{validator: validator.New()}
}
