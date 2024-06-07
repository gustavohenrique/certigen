package configurator

import (
	"log"
	"os"
	"sync"

	"github.com/spf13/viper"
)

var globalConfig *AppConfig

func Load(configFile string) *AppConfig {
	var config AppConfig
	if len(configFile) > 0 {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			log.Fatalln("Read in config:", err)
		}
		if err := viper.Unmarshal(&config); err != nil {
			log.Fatalln("Unmarshal config file:", err)
		}
	} else {
		if err := bindEnvs(&config); err != nil {
			log.Fatalln("Unmarshal from envvars", err)
		}
	}
	singleton(&config)
	return &config
}

func GetAppConfig() *AppConfig {
	if globalConfig != nil {
		return globalConfig
	}
	key := "CONFIG_FILE"
	configFile := os.Getenv(key)
	return Load(configFile)
}

func singleton(c *AppConfig) {
	var once sync.Once
	once.Do(func() {
		globalConfig = c
	})
}
