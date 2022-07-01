package operator

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	defaultFileConfig = &fileConfig{
		KubernetesAuthBackend: "kubernetes",
		MetricsAddress:        ":8080",
		Prefix:                "vkcc",
		AWS: awsFileConfig{
			DefaultTTL: 15 * time.Minute,
			MinTTL:     15 * time.Minute,
			Path:       "aws",
		},
	}
)

type fileConfig struct {
	// KubernetesAuthBackend is the mount path of the kubernetes auth
	// backend
	KubernetesAuthBackend string `yaml:"kubernetesAuthBackend"`
	// MetricsAddress is the address metrics are served on
	MetricsAddress string `yaml:"metricsAddress"`
	// Prefix is appended to objects created in Vault by the operator
	Prefix string `yaml:"prefix"`
	// AWS is configuration for the AWS secret backend
	AWS awsFileConfig `yaml:"aws"`
}

type awsFileConfig struct {
	// DefaultTTL is the default ttl of credentials that are issued for a role if not set
	DefaultTTL time.Duration `yaml:"defaultTTL"`
	// MinTTL is the minimum default-sts-ttl value allowed to set
	MinTTL time.Duration `yaml:"minTTL"`
	// Path is the mount path of the AWS secret backend
	Path string `yaml:"path"`
	// Rules that govern which service accounts can assume which roles
	Rules AWSRules `yaml:"rules"`
}

func loadConfigFromFile(file string) (*fileConfig, error) {
	cfg := defaultFileConfig

	if file == "" {
		return cfg, nil
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if strings.Contains(cfg.Prefix, "_") {
		return nil, fmt.Errorf("prefix must not contain a '_': %s", cfg.Prefix)
	}

	if cfg.AWS.Path == "" {
		return nil, fmt.Errorf("aws.path can't be empty")
	}

	return cfg, nil
}
