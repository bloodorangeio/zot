package compliance

type Config struct {
	Address    string
	Version    string
	Namespace  string
	Username   string
	Password   string
	OutputJSON bool
}

func NewConfig() *Config {
	return &Config{}
}
