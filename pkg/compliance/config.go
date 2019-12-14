package compliance

type Config struct {
	Address string
	Port    string
	Version string
  Namespace string
  Username string
  Password string
  UseHTTPS bool
  Token string
}

func NewConfig() *Config {
	return &Config{}
}
