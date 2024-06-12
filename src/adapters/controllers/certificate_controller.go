package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	dto "certigen/src/adapters/dto/http"
	"certigen/src/domain/ports"
	"certigen/src/shared/cryptus/certiman"
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
		h.logger.Info("starting")
	var res = dto.NewHttpResponse()
	var req dto.CreateCaCertificateRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("ca certificate invalid request:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	template := certiman.NewTemplate()
	template.SetCommonName(req.Name)
	template.AddOrganization(req.Organization)
	template.AddOrganizationalUnit(req.Team)
	template.SetExpirationDate(req.ExpiresAt.Time)
	ca, err := certiman.New().With(template).CreateRootCA()
	if err != nil {
		h.logger.Error("creating ca:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	cert := dto.CreateCertificateResponse{
		PrivateKey: ca.PrivateKey,
		PublicKey:  ca.PublicKey,
	}
	h.logger.Info("cert created")
	// certificate := models.Certificate{}
	// certificate.ID = random.Base58()
	// certificate.PrivateKeyPEM = ca.PrivateKey
	// certificate.PublicKeyPEM = ca.PublicKey
	// certificate.Environments = template.Localities()
	// certificate.Hosts = template.Hosts()
	// certificate.Projects = template.PermittedUriDomains()
	return c.JSON(http.StatusCreated, res.Success(cert))
}
