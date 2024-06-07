package converters

import (
	"certigen/src/adapters/dto"
	"certigen/src/adapters/dto/in"
	"certigen/src/adapters/dto/out"
	"certigen/src/domain/models"
)

type CertificateConverter struct {
}

func NewCertificateConverter() CertificateConverter {
	return CertificateConverter{}
}

func (c CertificateConverter) FromRequestToModel(input in.PisHttpRequest) models.Certificate {
	return models.Certificate{}
}

func (c CertificateConverter) FromTableToModel(input dto.PisTable) models.Certificate {
	output := models.Certificate{}
	output.ID = input.ID
	return output
}

func (c CertificateConverter) FromModelToHttpResponse(input models.Certificate) out.PisHttpResponse {
	output := out.PisHttpResponse{}
	output.ID = input.ID
	return output
}
