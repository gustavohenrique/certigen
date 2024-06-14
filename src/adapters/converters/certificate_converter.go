package converters

import (
	"certigen/src/adapters/dto"
	"certigen/src/domain/models"
)

type CertificateConverter struct {
}

func NewCertificateConverter() CertificateConverter {
	return CertificateConverter{}
}

func (c CertificateConverter) FromTableToModel(input dto.PisTable) models.Certificate {
	output := models.Certificate{}
	output.ID = input.ID
	return output
}
