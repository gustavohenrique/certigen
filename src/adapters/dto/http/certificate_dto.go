package http

import "certigen/src/domain/types/customdate"

type certificateRequest struct {
	Name         string                `json:"name" valid:"required"`
	Organization string                `json:"organization" valid:"required"`
	Team         string                `json:"team"`
	ExpiresAt    customdate.CustomDate `json:"expires_at" valid:"required"`
}

type CreateCaCertificateRequest struct {
	certificateRequest
}

type CreateIntermediateCertificateRequest struct {
	certificateRequest
	CaCert string `json:"ca_cert" valid:"required"`
	CaKey  string `json:"ca_key" valid:"required"`
}

type CreateServerCertificateRequest struct {
	CreateIntermediateCertificateRequest
	Environments []string `json:"environments"`
	Hosts        []string `json:"hosts"`
	Projects     []string `json:"projects" valid:"required"`
}

type CreateClientCertificateRequest struct {
	CreateServerCertificateRequest
}

type CreateCertificateResponse struct {
	ID         string `json:"id"`
	Serial     int64  `json:"serial"`
	ExpiresAt  string `json:"expires_at"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}
