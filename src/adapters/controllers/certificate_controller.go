package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"certigen/src/adapters/converters"
	"certigen/src/adapters/dto/in"
	"certigen/src/adapters/dto/out"
	"certigen/src/domain/ports"
	"certigen/src/shared/logger"
	"certigen/src/shared/validator"
)

type CertificateController struct {
	validator             validator.Validator
	logger                ports.Logger
	certificateRepository ports.CertificateRepository
	certificateConverter  converters.CertificateConverter
	repos                 ports.RepositoryContainer
}

func NewCertificateController(repos ports.RepositoryContainer) *CertificateController {
	return &CertificateController{
		logger:                logger.Get(),
		validator:             validator.New(),
		repos:                 repos,
		certificateRepository: repos.CertificateRepository(),
		certificateConverter:  converters.NewCertificateConverter(),
	}
}

// @Description Get pis by ID
// @Accept json
// @Produce json
// @Param id path string true "pis ID"
// @Router /v1/pis/{id} [get]
// @Success 200 {object} out.HttpResponse{data=out.PisHttpResponse}
// @Failure 404 {object} out.HttpResponse{}
func (h *CertificateController) ReadOneByID(c echo.Context) error {
	ctx := c.Request().Context()
	res := out.NewHttpResponse()
	found, err := h.certificateRepository.ReadOneByID(ctx, c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, res.Fail(err))
	}
	result := h.certificateConverter.FromModelToHttpResponse(found)
	return c.JSON(http.StatusOK, res.Success(result))
}

// @Description Create pis item
// @Accept json
// @Produce json
// @Param pis body in.PisHttpRequest true "Payload"
// @Router /v1/pis [post]
// @Success 201 {object} out.HttpResponse{data=out.PisHttpResponse}
// @Failure 400 {object} out.HttpResponse{}
// @Failure 500 {object} out.HttpResponse{}
func (h *CertificateController) Calculate(c echo.Context) error {
	var req in.PisHttpRequest
	res := out.NewHttpResponse()
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, res.Fail(err))
	}
	if err := h.validator.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, res.Fail(err))
	}
	item := h.certificateConverter.FromRequestToModel(req)
	return c.JSON(http.StatusCreated, res.Success(item))
}

func (h *CertificateController) Publish(c echo.Context) error {
	res := out.NewHttpResponse()
	word := c.Param("word")
	return c.JSON(http.StatusCreated, res.Success(word))
}
