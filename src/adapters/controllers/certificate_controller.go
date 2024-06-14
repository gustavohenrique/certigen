package controllers

import (
	"archive/zip"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

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
	var res = dto.NewHttpResponse()
	var req dto.CreateCaCertificateRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("ca certificate invalid request:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	if err := c.Validate(req); err != nil {
		h.logger.Error("invalid request", err)
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
	cert := dto.CreateCaCertificateResponse{
		PrivateKey: ca.PrivateKey,
		PublicKey:  ca.PublicKey,
	}
	return h.getPEMResponseOrZipFile(c, ca, cert)
}

func (h *CertificateController) CreateIntermediateCA(c echo.Context) error {
	var res = dto.NewHttpResponse()
	var req dto.CreateIntermediateCertificateRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("intermediate certificate invalid request:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	if err := c.Validate(req); err != nil {
		h.logger.Error("invalid request", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	template := certiman.NewTemplate()
	template.SetCommonName(req.Name)
	template.AddOrganization(req.Organization)
	template.AddOrganizationalUnit(req.Team)
	template.SetExpirationDate(req.ExpiresAt.Time)
	ca, err := certiman.New().
		With(template).
		WithKeyPair(req.CaCert, req.CaKey).
		CreateIntermediateCA()
	if err != nil {
		h.logger.Error("creating intermediate:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	cert := dto.CreateCaCertificateResponse{
		PrivateKey: ca.PrivateKey,
		PublicKey:  ca.PublicKey,
	}
	return h.getPEMResponseOrZipFile(c, ca, cert)
}

func (h *CertificateController) CreateServerCert(c echo.Context) error {
	var res = dto.NewHttpResponse()
	req, template, err := h.buildTemplateFromRequest(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	generated, err := certiman.New().
		With(template).
		WithKeyPair(req.CaCert, req.CaKey).
		CreateServerCert()
	if err != nil {
		h.logger.Error("creating server cert:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	cert := dto.CreateCertificateResponse{
		PrivateKey: generated.PrivateKey,
		PublicKey:  generated.PublicKey,
	}
	return h.getPEMResponseOrZipFile(c, generated, cert)
}

func (h *CertificateController) CreateClientCert(c echo.Context) error {
	var res = dto.NewHttpResponse()
	req, template, err := h.buildTemplateFromRequest(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	generated, err := certiman.New().
		With(template).
		WithKeyPair(req.CaCert, req.CaKey).
		CreateClientCert()
	if err != nil {
		h.logger.Error("creating client cert:", err)
		return c.JSON(http.StatusBadRequest, res.Error(err))
	}
	cert := dto.CreateCertificateResponse{
		PrivateKey: generated.PrivateKey,
		PublicKey:  generated.PublicKey,
	}
	return h.getPEMResponseOrZipFile(c, generated, cert)
}

func (h *CertificateController) buildTemplateFromRequest(c echo.Context) (dto.CreateCertificateRequest, *certiman.CertificateTemplate, error) {
	var req dto.CreateCertificateRequest
	var template = certiman.NewTemplate()
	if err := c.Bind(&req); err != nil {
		h.logger.Error("cannot bind request:", err)
		return req, template, err
	}
	if err := c.Validate(req); err != nil {
		h.logger.Error("invalid request:", err)
		return req, template, err
	}
	template.SetCommonName(req.Name)
	template.AddOrganization(req.Organization)
	template.AddOrganizationalUnit(req.Team)
	template.SetExpirationDate(req.ExpiresAt.Time)
	template.SetLocalities(req.Environments)
	template.SetHosts(req.Hosts)
	template.SetPermittedUriDomains(req.Services)
	return req, template, nil
}

func (h *CertificateController) zipIt(prefix, pubKey, privKey string) (string, error) {
	tempDir := os.TempDir()
	zipFilepath := filepath.Join(tempDir, prefix+"_certificates.zip")
	zipFile, err := os.Create(zipFilepath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %s", err)
	}
	defer zipFile.Close()
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	certWriter, err := zipWriter.Create("cert.pem")
	if err != nil {
		return "", fmt.Errorf("failed to create certificate file: %s", err)
	}
	if _, err := certWriter.Write([]byte(pubKey)); err != nil {
		return "", fmt.Errorf("failed to write certificate file: %s", err)
	}

	keyWriter, err := zipWriter.Create("cert.key")
	if err != nil {
		return "", fmt.Errorf("failed to create key file: %s", err)
	}
	if _, err := keyWriter.Write([]byte(privKey)); err != nil {
		return "", fmt.Errorf("failed to write key file: %s", err)
	}
	return zipFilepath, nil
}

func (h *CertificateController) getPEMResponseOrZipFile(c echo.Context, cert certiman.Certificate, body interface{}) error {
	var res = dto.NewHttpResponse()
	filename := c.QueryParam("download")
	if filename != "" {
		serial := cert.SerialNumber
		zipFile, err := h.zipIt(serial, cert.PublicKey, cert.PrivateKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, res.Error(err))
		}
		return c.Attachment(zipFile, filename)
	}
	return c.JSON(http.StatusCreated, res.Success(body))
}
