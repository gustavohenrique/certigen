package out

import "fmt"

type customError struct {
	Message string `json:"message"`
}
type HttpResponse struct {
	Data  interface{}  `json:"data,omitempty"`
	Error *customError `json:"error,omitempty"`
}

func NewHttpResponse() HttpResponse {
	return HttpResponse{}
}

func (r HttpResponse) Success(data interface{}) HttpResponse {
	r.Data = data
	r.Error = nil
	return r
}

func (r HttpResponse) Fail(err error, messages ...string) HttpResponse {
	r.Data = nil
	r.Error = &customError{Message: err.Error()}
	return r
}

func (r *HttpResponse) String() string {
	if r.Data != nil {
		return fmt.Sprintf("%s", r.Data)
	}
	return "Response data is empty"
}
