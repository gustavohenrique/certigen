package configurator

type httpServerConfig struct {
	Debug   bool     `env:"DEBUG" `
	Address string   `env:"HTTP_ADDRESS" yaml:"address" default:"0.0.0.0"`
	Port    int      `env:"HTTP_PORT" yaml:"port" default:"8001"`
	Origins []string `env:"HTTP_ALLOW_ORIGINS" yaml:"origins" default:"*"`
	TLS     struct {
		Enabled bool   `env:"HTTP_TLS_ENABLED" yaml:"enabled"`
		Key     string `env:"HTTP_TLS_KEY" yaml:"key"`
		Cert    string `env:"HTTP_TLS_CERT" yaml:"cert"`
	}
}
