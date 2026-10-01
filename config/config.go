package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level      string `yaml:"level" json:"level"`
	Format     string `yaml:"format" json:"format"`
	LogAllowed bool   `yaml:"log_allowed" json:"log_allowed"`
	LogDenied  bool   `yaml:"log_denied" json:"log_denied"`
}

// ListenConfig defines where the proxy listens for incoming connections.
type ListenConfig struct {
	Socket  string `yaml:"socket" json:"socket"`
	Address string `yaml:"address" json:"address"`
}

// Config is the top-level configuration.
type Config struct {
	Listen      ListenConfig   `yaml:"listen" json:"listen"`
	DockerSocket string        `yaml:"docker_socket" json:"docker_socket"`
	PoliciesPath   string      `yaml:"policies_path" json:"policies_path"`
	Logging     LoggingConfig  `yaml:"logging" json:"logging"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	dockerSocket := "/var/run/docker.sock"
	if env := os.Getenv("DOCKER_SOCKET"); env != "" {
		dockerSocket = env
	}
	return Config{
		Listen: ListenConfig{
			Socket: "/var/run/opa-docker-proxy.sock",
		},
		DockerSocket: dockerSocket,
		PoliciesPath:    "/etc/opa-docker-proxy/policies",
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			LogAllowed: true,
			LogDenied:  true,
		},
	}
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	if c.Listen.Socket == "" && c.Listen.Address == "" {
		return fmt.Errorf("either listen.socket or listen.address must be configured")
	}
	if c.DockerSocket == "" {
		return fmt.Errorf("docker_socket must not be empty")
	}
	if c.PoliciesPath == "" {
		return fmt.Errorf("policies_path must not be empty")
	}
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}
	validFormats := map[string]bool{"text": true, "json": true}
	if !validFormats[c.Logging.Format] {
		return fmt.Errorf("logging.format must be one of: text, json")
	}
	return nil
}

// LoadConfig reads a YAML config file and returns a Config.
// It applies defaults first, then overrides with values from the file.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && path == "" {
			// Default path not found — just return defaults.
			return cfg, cfg.Validate()
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	return cfg, cfg.Validate()
}
