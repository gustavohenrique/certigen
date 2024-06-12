package http

import "encoding/json"

type HttpResponse struct {
	Data interface{} `json:"data,omitempty"`
	Err  error       `json:"error,omitempty"`
}

func NewHttpResponse() HttpResponse {
	return HttpResponse{}
}

func (r HttpResponse) Success(data interface{}) HttpResponse {
	r.Data = data
	r.Err = nil
	return r
}

func (r HttpResponse) Error(err error, messages ...string) HttpResponse {
	r.Data = nil
	r.Err = err
	return r
}

func (r *HttpResponse) String() string {
	if r.Data != nil {
		b, err := json.Marshal(r.Data)
		if err != nil {
			return "Marshal error"
		}
		return string(b)
	}
	return "Response data is empty"
}
