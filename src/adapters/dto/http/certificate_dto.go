package http

import "time"

type certificateRequest struct {
	Name         string    `json:"name"`
	Organization string    `json:"organization"`
	Team         string    `json:"team"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type CreateCaCertificateRequest struct {
	certificateRequest
}

type CreateIntermediateCertificateRequest struct {
	certificateRequest
	CaCert string `json:"ca_cert"`
	CaKey  string `json:"ca_key"`
}

type CreateServerCertificateRequest struct {
	CreateIntermediateCertificateRequest
	Environments []string `json:"environments"`
	Hosts        []string `json:"hosts"`
	Projects     []string `json:"projects"`
}

type CreateClientCertificateRequest struct {
	CreateServerCertificateRequest
}
