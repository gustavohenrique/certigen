package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"certigen/src/adapters/controllers"
	"certigen/src/adapters/repositories"
	"certigen/src/drivers/datastores"
	"certigen/src/drivers/servers/httpserver"
	"certigen/src/shared/configurator"
	"certigen/src/shared/logger"
)

func init() {
	var configFile string
	flag.StringVar(&configFile, "config", "", "Configuration file")
	flag.Parse()
	config := configurator.Load(configFile)
	logger.Init(logger.Config{
		Level:      config.Log.Level,
		Format:     config.Log.Format,
		Output:     config.Log.Output,
		PrettyJSON: config.Log.Indent,
	})
}

func main() {
	ds := datastores.New()
	repos := repositories.NewRepositoryContainer(ds)

	httpServer := httpserver.New()
	httpServer.AddHealthCheck("/health", ds)
	httpServer.UseRequestValidator()
	httpServer.UseDefaultMiddlewares()
	httpServer.AttachSwaggerToPath("/docs")
	httpServer.ServeHtml("/web")
	httpServer.ServeStaticFiles("/static")
	router := httpServer.Router()
	v1 := router.Group("/api/v1")

	certificateController := controllers.NewCertificateController(repos)
	certificateGroup := v1.Group("/certificate")
	certificateGroup.GET("/:id", certificateController.ReadOneByID)
	certificateGroup.POST("/calculate", certificateController.Calculate)
	certificateGroup.GET("/pub/:word", certificateController.Publish)

	go httpServer.Start()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	<-quit
}
