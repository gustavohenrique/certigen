package configurator

type AppConfig struct {
	Log struct {
		Level  string `env:"LOG_LEVEL" yaml:"level" default:"info"`
		Output string `env:"LOG_OUTPUT" yaml:"output" default:"stdout"`
		Format string `env:"LOG_FORMAT" yaml:"format,omitempty" default:"text"`
		Indent bool   `env:"LOG_INDENT" yaml:"indent,omitempty" default:"false"`
	}
	HttpServer struct {
		Debug   bool     `env:"DEBUG" `
		Address string   `env:"HTTP_ADDRESS" yaml:"address" default:"0.0.0.0"`
		Port    int      `env:"HTTP_PORT" yaml:"port" default:"8001"`
		Origins []string `env:"HTTP_ALLOW_ORIGINS" yaml:"origins" default:"*"`
		TLS     struct {
			Enabled bool   `env:"HTTP_TLS_ENABLED" yaml:"enabled"`
			Key     string `env:"HTTP_TLS_KEY" yaml:"key"`
			Cert    string `env:"HTTP_TLS_CERT" yaml:"cert"`
		}
	} `yaml:"http_server"`
	Sqlite struct {
		Address string `env:"SQLITE_ADDRESS" yaml:"address" default:":memory:"`
	} `yaml:"sqlite"`

	Ca struct {
		PublicKey  string `env:"OCSP_CA_CERT"`
		PrivateKey string `env:"OCSP_CA_KEY"`
	}
}
