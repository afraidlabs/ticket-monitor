package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// Config is a slice of every SiteConfig supplied
type Config []*SiteConfig

// SiteConfig are user supplied parameters for monitoring a certain Supreme region.
type SiteConfig struct {
	// URL is the initial URL where the WebAssembly
	// and Javascript file scanning begins.
	// It is a required field.
	URL string `json:"url"`

	// ProxyURL is an optional field where one may
	// specify a Proxy URL per RFC 3986.
	ProxyURL string `json:"proxyUrl"`

	// ScanDepth is a customisable the depth limit
	// of up to 255 URLs. It is a required field.
	ScanDepth uint8 `json:"scanDepth"`

	// WebhookURL is a Discord Webhook URL where
	// updates on ticket changes will be sent.
	// It is a required field.
	WebhookURL string `json:"webhookUrl"`

	// Headers is an optional object where you can
	// specify request headers sent with all
	// requests to Supreme.
	Headers map[string]string `json:"headers"`
}

// readConfig reads and unmarshals a the config supplied in the
// filename parameter and returns a Config. If it fails an error is returned.
func readConfig(filename string) (Config, error) {
	cfgFile, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	var cfg Config

	err = json.Unmarshal(cfgFile, &cfg)

	if err != nil {
		return nil, err
	}

	for i, siteConfig := range cfg {
		if siteConfig.URL == "" {
			return nil, fmt.Errorf("%w at index %v", ErrInvalidURL, i)
		}

		if siteConfig.ScanDepth == 0 {
			return nil, fmt.Errorf("%w at index %v", ErrInvalidScanDepth, i)
		}

		if siteConfig.WebhookURL == "" {
			return nil, fmt.Errorf("%w at index %v", ErrInvalidWebhookURL, i)
		}
	}

	return cfg, nil
}
