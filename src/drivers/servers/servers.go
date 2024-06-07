package servers

import (
	"github.com/labstack/echo/v4"

	"certigen/src/drivers/datastores"
)

type HttpServer interface {
	UseDefaultMiddlewares()
	AttachSwaggerToPath(path string)
	AddHealthCheck(path string, ds datastores.DataStore)
	UseRequestValidator()
	ServeHtml(path string)
	ServeStaticFiles(path string)
	Start(address ...string) error
	Router() *echo.Echo
}
