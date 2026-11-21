// Package config provides configuration loading and validation for
// opa-docker-proxy.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level      string `json:"level"       yaml:"level"`
	Format     string `json:"format"      yaml:"format"`
	LogAllowed bool   `json:"log_allowed" yaml:"log_allowed"`
	LogDenied  bool   `json:"log_denied"  yaml:"log_denied"`
	LogOPA     bool   `json:"log_opa"  yaml:"log_opa"`
}

// ListenConfig defines where the proxy listens for incoming connections.
type ListenConfig struct {
	Socket  string `json:"socket"  yaml:"socket"`
	Address string `json:"address" yaml:"address"`
}

// Config is the top-level configuration.
type Config struct {
	Listen       ListenConfig  `json:"listen"        yaml:"listen"`
	DockerSocket string        `json:"docker_socket" yaml:"docker_socket"`
	PoliciesPath string        `json:"policies_path" yaml:"policies_path"`
	Logging      LoggingConfig `json:"logging"       yaml:"logging"`
	// Policy is passed to the Rego policies as data.config. Its schema and
	// validation live in policies/00_config.rego.
	Policy map[string]any `json:"policy" yaml:"policy"`
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
		PoliciesPath: "/etc/opa-docker-proxy/policies",
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			LogAllowed: true,
			LogDenied:  true,
			LogOPA:     true,
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

// DefaultConfigPath is used when no config path is given on the command line.
const DefaultConfigPath = "/etc/opa-docker-proxy/config.yaml"

// LoadConfig reads a YAML config file and returns a Config.
// It applies defaults first, then overrides with values from the file.
// An empty path means DefaultConfigPath, which may be absent (built-in
// defaults are used). An explicitly given path must exist.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	explicit := path != ""
	if !explicit {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
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
