package testify

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	JSON = "application/json"
	HTML = "text/html"
)

type HttpMock struct {
	ContentType string
	StatusCode  int
	Data        string
}

func (hc HttpMock) IsHTML() bool {
	return hc.ContentType == HTML
}

func WithHttpMock(ts *testing.T, name string, mock HttpMock, fn func(tt *testing.T, url string)) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusCode := 200
		if mock.StatusCode > 0 {
			statusCode = mock.StatusCode
		}
		w.WriteHeader(statusCode)

		contentType := JSON
		if mock.ContentType != "" {
			contentType = mock.ContentType
		}
		w.Header().Add("Content-Type", contentType)
		w.Write([]byte(mock.Data))
	}))
	defer mockServer.Close()
	ts.Run(name, func(t *testing.T) {
		fn(t, mockServer.URL)
	})
}
