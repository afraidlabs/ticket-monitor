package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// Config is the main configuration for this application
type Config struct {
	// Sites is a slice of every specified
	// SiteConfig in the configuration file.
	Sites []SiteConfig `json:"sites"`

	// WebhookURL is a Discord Webhook URL where
	// updates on site changes will be sent.
	// It is a required field.
	WebhookURL string `json:"webhookUrl"`

	// BucketName is the name of the
	// Google Cloud Storage Bucket where
	// new files will be saved to.
	BucketName string `json:"bucketName"`
}

// SiteConfig are user supplied parameters for monitoring a certain Supreme region.
type SiteConfig struct {
	// URL is the initial URL where the WebAssembly
	// and Javascript file scanning begins.
	// It is a required field.
	URL string `json:"url"`

	// Delay is the delay in milliseconds between
	// a cycle of scanning URLs.
	Delay int64 `json:"delay"`

	// ProxyURL is an optional field where one may
	// specify a proxy per RFC 3986.
	ProxyURL string `json:"proxyUrl"`

	// ScanDepth is a customisable the depth limit
	// of up to 255.
	ScanDepth uint8 `json:"scanDepth"`

	// Headers is an optional object where you can
	// specify request headers sent with all
	// requests to Supreme.
	Headers map[string]string `json:"headers"`
}

// readConfig reads and unmarshals a the config supplied in the
// path parameter and returns a Config. If it fails an error is returned.
func readConfig(path string) (*Config, error) {
	cfgFile, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	var config *Config

	err = json.Unmarshal(cfgFile, &config)

	if err != nil {
		return nil, err
	}

	for i, siteConfig := range config.Sites {
		if siteConfig.URL == "" {
			return nil, fmt.Errorf("%w at index %v", ErrInvalidURL, i)
		}
	}

	return config, nil
}
