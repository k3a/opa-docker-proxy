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

// IsolationConfig configures resource isolation (see package isolation).
// The -i / --isolation-name flags enable it too and override Name.
type IsolationConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Name is the label value identifying "this" proxy's resources. Keep it
	// stable: resources created under another name are invisible/untouchable.
	// Defaults to a hash of the working directory.
	Name string `json:"name" yaml:"name"`
	// Mode is "full" (default; private-daemon view) or "writes" (reads open,
	// only changes are restricted to own resources).
	Mode string `json:"mode" yaml:"mode"`
}

// Config is the top-level configuration.
type Config struct {
	Listen       ListenConfig    `json:"listen"        yaml:"listen"`
	DockerSocket string          `json:"docker_socket" yaml:"docker_socket"`
	PoliciesPath string          `json:"policies_path" yaml:"policies_path"`
	Logging      LoggingConfig   `json:"logging"       yaml:"logging"`
	Isolation    IsolationConfig `json:"isolation"   yaml:"isolation"`
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

	if m := c.Isolation.Mode; m != "" && m != "full" && m != "writes" {
		return fmt.Errorf("isolation.mode must be one of: full, writes")
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

// unscopedWithoutIsolation are policy.allow tokens that change existing
// objects, which is only scoped to the client's own when isolation is on.
// (images_write is scoped too: with isolation, only images built or
// committed through the proxy can be deleted, pushed or tagged.)
var unscopedWithoutIsolation = map[string]bool{
	"containers_control": true,
	"containers_delete":  true,
	"exec":               true,
	"volumes_write":      true,
	"networks_write":     true,
	"images_write":       true,
}

// UnscopedWriteTokens returns the policy.allow entries that let clients
// change objects they did not create: every enabled write token that touches
// existing objects, unless isolation is on.
func (c Config) UnscopedWriteTokens(isolated bool) []string {
	list, _ := c.Policy["allow"].([]any)

	var out []string

	for _, v := range list {
		t, _ := v.(string)
		if !isolated && unscopedWithoutIsolation[t] {
			out = append(out, t)
		}
	}

	return out
}
