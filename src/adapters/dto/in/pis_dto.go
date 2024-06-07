package in

import "errors"

type PisHttpRequest struct {
	Company string `json:"cnpj"`
}

func (p *PisHttpRequest) Validate() error {
	if p.Company == "" {
		return errors.New("company is empty")
	}
	return nil
}
