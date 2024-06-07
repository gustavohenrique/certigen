package configurator

type AppConfig struct {
	Log struct {
		Level  string `env:"LOG_LEVEL" yaml:"level" default:"info"`
		Output string `env:"LOG_OUTPUT" yaml:"output" default:"stdout"`
		Format string `env:"LOG_FORMAT" yaml:"format,omitempty" default:"text"`
		Indent bool   `env:"LOG_INDENT" yaml:"indent,omitempty" default:"false"`
	}
	HttpServer httpServerConfig `yaml:"http_server"`
	Sqlite     struct {
		Address string `env:"SQLITE_ADDRESS" yaml:"address" default:":memory:"`
	} `yaml:"sqlite"`
}
