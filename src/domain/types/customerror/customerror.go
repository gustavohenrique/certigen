package customerror

import (
	"net/http"
	"strings"
)

type grpcCode uint32

type CustomError struct {
	code            grpcCode
	message         string
	originalMessage string
}

const (
	unknown             = 2  // codes.Unknown
	invalid             = 3  // codes.InvalidArgument
	not_found           = 5  // codes.NotFound
	already_exists      = 6  // codes.AlreadyExists
	permission_denied   = 7  // codes.PermissionDenied
	resource_exhausted  = 8  // codes.ResourceExhausted
	failed_precondition = 9  // codes.FailedPrecondition
	internal            = 13 // codes.Internal
	unavailable         = 14 // codes.Unavailable
	unauthenticated     = 16 // codes.Unauthenticated
)

var httpCodes = map[grpcCode]int{
	unknown:             http.StatusConflict,
	internal:            http.StatusInternalServerError,
	invalid:             http.StatusBadRequest,
	not_found:           http.StatusNotFound,
	already_exists:      http.StatusConflict,
	unauthenticated:     http.StatusUnauthorized,
	unavailable:         http.StatusInternalServerError,
	permission_denied:   http.StatusForbidden,
	failed_precondition: http.StatusPreconditionFailed,
	resource_exhausted:  http.StatusTooManyRequests,
}

var errorsMap = map[string]grpcCode{
	"violates":                    invalid,
	"valid":                       invalid,
	"empty":                       invalid,
	"invalid token":               invalid,
	"parse":                       invalid,
	"duplicate key":               already_exists,
	"no rows in result":           not_found,
	"no results found":            not_found,
	"permission denied":           permission_denied,
	"no responders available":     unavailable,
	"connect: connection refused": unavailable,
	"connection":                  unavailable,
	"mismatch":                    failed_precondition,
	"expired":                     permission_denied,
}

func (e *CustomError) Error() string {
	return e.message
}

func Unavailable(err error, message string) error {
	return Wrap(getInstance(unavailable, err, message))
}

func Denied(err error, message string) error {
	return Wrap(getInstance(permission_denied, err, message))
}

func PreConditionFailed(err error, message string) error {
	return Wrap(getInstance(failed_precondition, err, message))
}

func InvalidInput(err error, message string) error {
	return Wrap(getInstance(invalid, err, message))
}

func Unauthenticated(err error, message string) error {
	return Wrap(getInstance(unauthenticated, err, message))
}

func NotFound(err error, message string) error {
	return getInstance(not_found, err, message)
}

func Wrap(err error) error {
	if err == nil {
		return nil
	}
	code := getCodeFrom(err)
	return getInstance(code, err)
}

func StatusCodeFrom(err error) int {
	if err != nil {
		code := getCodeFrom(err)
		return httpCodes[code]
	}
	return http.StatusExpectationFailed
}

func getCodeFrom(err error) grpcCode {
	customError, isCustomError := err.(*CustomError)
	if !isCustomError {
		return detectCodeAccordingToMessage(err)
	}
	if customError.code > 0 {
		return customError.code
	}
	return detectCodeAccordingToMessage(err)
}

func detectCodeAccordingToMessage(err error) grpcCode {
	errorMessage := err.Error()
	for message, code := range errorsMap {
		if strings.Contains(strings.ToLower(errorMessage), strings.ToLower(message)) {
			return code
		}
	}
	return internal
}

func getInstance(code grpcCode, err error, message ...string) *CustomError {
	customError := &CustomError{}
	customError.code = code
	if err != nil {
		customError.originalMessage = err.Error()
	}
	if len(message) > 0 {
		customError.message = message[0]
	}
	return customError
}
