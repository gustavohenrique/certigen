package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"certigen/src/domain/ports"
	"certigen/src/shared/logger"
)

type CertificateController struct {
	logger  ports.Logger
	repos   ports.RepositoryContainer
	handler func(w http.ResponseWriter, r *http.Request)
}

func NewCertificateController(repos ports.RepositoryContainer) *CertificateController {
	return &CertificateController{
		logger: logger.Get(),
		repos:  repos,
	}
}

func (h *CertificateController) CreateCA(c echo.Context) error {
	h.handler(c.Response().Writer, c.Request())
	return nil
}
