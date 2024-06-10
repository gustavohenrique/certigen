package controllers

import (
	"context"
	"math/big"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"certigen/src/domain/ports"
	"certigen/src/shared/configurator"
	"certigen/src/shared/cryptus/certiman/ocspresponder"
	"certigen/src/shared/cryptus/certiman/ocspresponder/ocsp"
	"certigen/src/shared/logger"
)

type OcspController struct {
	logger  ports.Logger
	repos   ports.RepositoryContainer
	handler func(w http.ResponseWriter, r *http.Request)
}

func NewOcspController(repos ports.RepositoryContainer) *OcspController {
	config := configurator.GetAppConfig()
	responder := ocspresponder.NewResponder(&ocspresponder.Config{
		CaCert:   config.Ca.PublicKey,
		OcspCert: config.HttpServer.TLS.Cert,
		OcspKey:  config.HttpServer.TLS.Key,
	})
	return &OcspController{
		logger: logger.Get(),
		repos:  repos,
		handler: responder.MakeHttpHandler(func(ctx context.Context, serial *big.Int) (int, int, time.Time) {
			var now time.Time
			if serial == nil {
				return ocsp.Unknown, ocsp.Unspecified, now
			}
			found, err := repos.CertificateRepository().ReadOneBySerial(ctx, *serial)
			if err != nil {
				return ocsp.Unknown, ocsp.Unspecified, now
			}
			if found.Revoked() {
				return ocsp.Revoked, found.RevokedReason, *found.RevokedAt
			}
			return ocsp.Good, ocsp.Unspecified, now
		}),
	}
}

func (h *OcspController) OnPOST(c echo.Context) error {
	h.handler(c.Response().Writer, c.Request())
	return nil
}

func (h *OcspController) OnGET(c echo.Context) error {
	h.handler(c.Response().Writer, c.Request())
	return nil
}
