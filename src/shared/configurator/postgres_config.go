package configurator

type postgresConfig struct {
	URL             string `env:"POSTGRES_URL" yaml:"url" default:"postgres://admin:123456@127.0.0.1/maindb?sslmode=disable"`
	MaxOpenConns    int    `env:"POSTGRES_MAX_OPEN_CONN" yaml:"max_open_conns" default:"10"`
	MaxIdleConns    int    `env:"POSTGRES_MAX_IDLE_CONN" yaml:"max_idle_conns" default:"10"`
	MaxConnLifetime int    `env:"POSTGRES_MAX_CONN_LIFETIME" yaml:"max_conn_lifetime" default:"480"`
}
