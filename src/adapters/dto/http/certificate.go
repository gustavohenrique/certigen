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
	Name         string                `json:"name" valid:"required"`
	Organization string                `json:"organization" valid:"required"`
	Team         string                `json:"team"`
	ExpiresAt    customdate.CustomDate `json:"expires_at" valid:"required"`
	CaCert       string                `json:"cert" valid:"required"`
	CaKey        string                `json:"key" valid:"required"`
}

type CreateCertificateRequest struct {
	CreateIntermediateCertificateRequest
	Environments []string `json:"environments"`
	Hosts        []string `json:"hosts"`
	Services     []string `json:"allow_connections_to" valid:"required"`
}

type CreateCaCertificateResponse struct {
	PrivateKey string `json:"key"`
	PublicKey  string `json:"cert"`
}

type CreateCertificateResponse struct {
	ID         string `json:"id"`
	Serial     int64  `json:"serial"`
	ExpiresAt  string `json:"expires_at"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}
