package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/labstack/echo/v4"
)

type HttpTest struct {
	router *echo.Echo
}

func OnGET(url string, fn echo.HandlerFunc) *HttpTest {
	router := getRouter()
	router.GET(url, fn)
	return &HttpTest{
		router: router,
	}
}

func OnPOST(url string, fn echo.HandlerFunc) *HttpTest {
	router := getRouter()
	router.POST(url, fn)
	return &HttpTest{
		router: router,
	}
}

func OnPUT(url string, fn echo.HandlerFunc) *HttpTest {
	router := getRouter()
	router.PUT(url, fn)
	return &HttpTest{
		router: router,
	}
}

func OnPATCH(url string, fn echo.HandlerFunc) *HttpTest {
	router := getRouter()
	router.PATCH(url, fn)
	return &HttpTest{
		router: router,
	}
}

func OnDELETE(url string, fn echo.HandlerFunc) *HttpTest {
	router := getRouter()
	router.DELETE(url, fn)
	return &HttpTest{
		router: router,
	}
}

func (h HttpTest) ServeHTTP(req *http.Request, data interface{}) (*http.Response, error) {
	resp := httptest.NewRecorder()
	h.router.ServeHTTP(resp, req)
	rawResponse := resp.Result()
	body, err := io.ReadAll(rawResponse.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(body, data)
	return rawResponse, err
}

func (h *HttpTest) Use(mid echo.MiddlewareFunc) *HttpTest {
	h.router.Use(mid)
	return h
}

func getRouter() *echo.Echo {
	httpServer := New()
	httpServer.UseRequestValidator()
	return httpServer.Router()
}
