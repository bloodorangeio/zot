package compliance

type Config struct {
	Address string
	Port    string
	Version string
  Namespace string
}

func NewConfig() *Config {
	return &Config{}
}
