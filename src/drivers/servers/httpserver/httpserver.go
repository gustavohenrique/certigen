package httpserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"certigen/assets"
	"certigen/src/drivers/datastores"
	"certigen/src/drivers/servers"
	_ "certigen/src/drivers/servers/httpserver/docs"
	"certigen/src/shared/configurator"
	"certigen/src/shared/logger"
)

// @title My example application
// @version 1.0
// @contact.name My Team
// @contact.url https://mycompany.com
// @contact.email contact@mycompany.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8001
// @schemes http https
// @BasePath /v1

type httpServer struct {
	rawServer *echo.Echo
	config    httpServerConfig
}

type httpServerConfig struct {
	Debug      bool
	Address    string
	Origins    []string
	TlsEnabled bool
	TlsKey     string
	TlsCert    string
}

func New() servers.HttpServer {
	appConfig := configurator.GetAppConfig().HttpServer
	config := httpServerConfig{
		Debug:      appConfig.Debug,
		Address:    fmt.Sprintf("%s:%d", appConfig.Address, appConfig.Port),
		Origins:    appConfig.Origins,
		TlsEnabled: appConfig.TLS.Enabled,
		TlsKey:     appConfig.TLS.Key,
		TlsCert:    appConfig.TLS.Cert,
	}
	rawServer := echo.New()
	rawServer.Debug = config.Debug
	rawServer.HideBanner = true
	return &httpServer{
		config:    config,
		rawServer: rawServer,
	}
}

func (s *httpServer) Router() *echo.Echo {
	return s.rawServer
}

func (s *httpServer) UseDefaultMiddlewares() {
	e := s.rawServer
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     s.config.Origins,
		AllowCredentials: true,
		AllowMethods: []string{
			http.MethodOptions,
			http.MethodGet,
			http.MethodPut,
			http.MethodPost,
			http.MethodDelete,
			http.MethodHead,
		},
		ExposeHeaders: []string{
			"grpc-status",
			"grpc-message",
			"grpc-timeout",
			"content-length",
			"X-Auth-Token",
		},
		AllowHeaders: []string{
			"Accept",
			"Accept-Encoding",
			"Authorization",
			"XMLHttpRequest",
			"X-Requested-With",
			"X-Request-ID",
			"X-Auth-Token",
			"X-User-Id",
			"X-user-agent",
			"X-grpc-web",
			"grpc-status",
			"grpc-message",
			"grpc-timeout",
			"Content-Type",
			"Content-Length",
			"User-Agent",
			"X-Amzn-Trace-Id",
			"X-Forwarded-For",
			"X-Forwarded-Port",
			"X-Real-Ip",
			"X-SDK-Version",
			"X-SDK-Agent",
		},
	}))
	e.Use(middleware.BodyLimit("10M"))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
		Skipper: func(c echo.Context) bool {
			return strings.Contains(c.Request().URL.Path, "docs")
		},
	}))
}

func (s *httpServer) AttachSwaggerToPath(path string) {
	e := s.rawServer
	suffix := "/*"
	if strings.HasSuffix(path, suffix) {
		e.GET(path, s.addSwaggerDocs())
		return
	}
	e.GET(path+suffix, s.addSwaggerDocs())
}

func (s *httpServer) AddHealthCheck(path string, ds datastores.DataStore) {
	e := s.rawServer
	e.GET(path, func(c echo.Context) error {
		res := c.Response()
		res.Header().Set("Expires", time.Unix(0, 0).Format(time.RFC1123))
		res.Header().Set("Cache-Control", "no-cache, private, max-age=0")
		res.Header().Set("Pragma", "no-cache")
		res.Header().Set("X-Accel-Expires", "0")
		isDbConnected := ds.Sqlite().Ping() == nil
		payload := map[string]interface{}{
			"build":           logger.BUILD_DATE,
			"commit":          logger.COMMIT_HASH,
			"is_db_connected": isDbConnected,
		}
		status := http.StatusOK
		if !isDbConnected {
			status = http.StatusServiceUnavailable
		}
		return c.JSON(status, payload)
	})
}

func (s *httpServer) ServeHtml(path string) {
	s.serveEmbedWebPage(strings.ReplaceAll(path, "/", ""), assets.NewWebPage())
}

func (s *httpServer) serveEmbedWebPage(path string, webPage assets.WebPage) {
	e := s.rawServer
	group := e.Group(path)
	group.GET("", func(c echo.Context) error {
		return c.Redirect(307, path+"/index.html")
	})
	group.GET("/:filename", func(c echo.Context) error {
		filename := c.Param("filename")
		if !strings.HasSuffix(filename, ".html") {
			filename = filename + ".html"
		}
		content, _ := webPage.Lookup(filename)
		if content == "" {
			return c.String(http.StatusNotFound, fmt.Sprintf("Not found: %s\n", filename))
		}
		tpl := Parse(content, map[string]interface{}{
			"message": "Hello World!",
		})
		return c.HTML(http.StatusOK, tpl)
	})
}

func (s *httpServer) ServeStaticFiles(path string) {
	s.serveEmbedStaticFiles(strings.ReplaceAll(path, "/", ""), assets.NewStaticFile())
}

func (s *httpServer) serveEmbedStaticFiles(path string, staticFile assets.StaticFile) {
	e := s.rawServer
	files := staticFile.GetFS()
	route := "/" + path + "/"
	e.GET(route+"*", echo.WrapHandler(http.StripPrefix(route, files)))
}

func (s *httpServer) Start(address ...string) error {
	addr := s.config.Address
	if len(address) > 0 && address[0] != "" {
		addr = address[0]
	}
	e := s.rawServer
	go func() {
		if s.config.TlsEnabled {
			key := s.config.TlsKey
			cert := s.config.TlsCert
			log.Fatal(e.StartTLS(addr, cert, key))
		}
		log.Fatal(e.Start(addr))
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	<-quit
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}
