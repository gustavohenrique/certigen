package controllers_test

import (
	"fmt"
	"testing"

	"certigen/src/adapters/controllers"
	dto "certigen/src/adapters/dto/http"
	"certigen/src/drivers/servers/httpserver"
	"certigen/src/shared/stringfy"
	"certigen/src/shared/testify"
	"certigen/src/shared/testify/assert"
	"certigen/src/shared/testify/httpclient"
)

func TestCertificateController(tt *testing.T) {
	testify.It(tt, "CreateCA", func(ts *testing.T) {
		testify.It(ts, "Should create CA", func(t *testing.T) {
			var controller = controllers.NewCertificateController(nil)
			var url = "/certificate/ca"
			var payload = `{
				"expires_at": "2050-10-15",
				"organization": "my corp inc.",
				"name": "my ca",
				"team": "x-team"
			}`
			req := httpclient.New().DoPOST(url, payload)
			server := httpserver.OnPOST("/certificate/ca", controller.CreateCA)
			var body dto.HttpResponse
			res, err := server.ServeHTTP(req, &body)

			assert.Nil(t, err, fmt.Sprintf("Expected nil but got %s", err))
			assert.Equal(t, res.StatusCode, 201)

			var data dto.CreateCertificateResponse
			assert.Nil(t, stringfy.FromJSON(body.String(), &data))
			assert.True(t, len(data.PrivateKey) > 1)
			assert.True(t, len(data.PublicKey) > 1)
		})
	})
}
