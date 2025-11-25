package config

type Config struct {
	Environment string
	Database    struct {
		Host     string
		Port     int
		User     string
		Password string
		Name     string
	}
	Server struct {
		Address string
	}
	HSM struct {
		LibraryPath string
		TokenLabel  string
		Pin         string
	}
	AuditService struct {
		Enabled bool   `mapstructure:"enabled"`
		BaseURL string `mapstructure:"base_url"`
	} `mapstructure:"audit_service"`
}

func (c *Config) DatabaseConnectionString() string {
	return "host=" + c.Database.Host +
		" port=" + string(rune(c.Database.Port)) +
		" user=" + c.Database.User +
		" password=" + c.Database.Password +
		" dbname=" + c.Database.Name +
		" sslmode=disable"
}

func LoadConfig() *Config {
	// Dummy config for demonstration; replace with actual config loading logic
	return &Config{
		Environment: "development",
		Database: struct {
			Host     string
			Port     int
			User     string
			Password string
			Name     string
		}{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "password",
			Name:     "mydb",
		},
		Server: struct{ Address string }{
			Address: ":8080",
		},
		HSM: struct {
			LibraryPath string
			TokenLabel  string
			Pin         string
		}{
			LibraryPath: "/usr/local/lib/softhsm/libsofthsm2.so",
			TokenLabel:  "mytoken",
			Pin:         "1234",
		},
	}
}

func (c *Config) IsAuditEnabled() bool {
	return c.AuditService.Enabled && c.AuditService.BaseURL != ""
}
