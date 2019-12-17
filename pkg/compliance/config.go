package compliance

type Config struct {
	Address   string
	Port      string
	Version   string
	Namespace string
	Userpass  string
	UseHTTPS  bool
}

func NewConfig() *Config {
	return &Config{}
}
