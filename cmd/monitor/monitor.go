package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mvdan.cc/xurls/v2"
)

// Monitor is an instance of a monitor which scans for changes
// from the specified SiteConfig.
type Monitor struct {
	// Client carries out all requests for the
	// monitor instance.
	Client *http.Client

	// Header is a http.Header struct using the
	// specified Headers in the SiteConfig
	Header http.Header

	// SiteConfig are the parameters for monitoring
	// Supreme's website.
	SiteConfig *SiteConfig

	// FileHashes is makeshift Set which contains
	// all previously detected files.
	FileHashes map[string]bool
}

var (
	// ErrInvalidURL occurs when no URL is specified
	ErrInvalidURL = errors.New("monitor: no url specified")

	// ErrInvalidScanDepth occurs when the ScanDepth is equal to zero
	ErrInvalidScanDepth = errors.New("monitor: no scanDepth specified")

	// ErrInvalidWebhookURL occurs when no URL is specified
	ErrInvalidWebhookURL = errors.New("monitor: no webhookUrl specified")

	// ErrInvalidStatus occurs when a response's status is not 200 OK
	ErrInvalidStatus = errors.New("monitor: invalid status")

	// URLBlacklist contains a list of URLs to ignore on in the monitor
	URLBlacklist = map[string]bool{
		"google-analytics.com/ga.js": true,
	}

	// HostBlacklist contains a list of hostnames to ignore on in the monitor
	HostBlacklist = map[string]bool{
		"cdn.mxpnl.com":                 true,
		"www.google.com":                true,
		"songbird.cardinalcommerce.com": true,
	}
)

// createMonitor creates a Monitor with the supplied siteConfig
// parameter. If it fails an error is returned.
func createMonitor(siteConfig *SiteConfig) (*Monitor, error) {
	if siteConfig.URL == "" {
		return nil, ErrInvalidURL
	}

	if siteConfig.ScanDepth == 0 {
		return nil, ErrInvalidScanDepth
	}

	if siteConfig.WebhookURL == "" {
		return nil, ErrInvalidWebhookURL
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	header := http.Header{}

	for key, value := range siteConfig.Headers {
		header.Set(key, value)
	}

	if siteConfig.ProxyURL != "" {
		proxyURL, err := url.Parse(siteConfig.ProxyURL)
		if err != nil {
			return nil, err
		}

		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	return &Monitor{
		Client:     client,
		Header:     header,
		SiteConfig: siteConfig,
		FileHashes: make(map[string]bool),
	}, nil
}

// InitialRequest uses the URL specified in the SiteConfig to
// gather the initial set of URLs. If it fails an error is returned.
func (m *Monitor) InitialRequest() ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, m.SiteConfig.URL, nil)

	if err != nil {
		return nil, err
	}

	if len(m.Header) > 0 {
		req.Header = m.Header
	}

	resp, err := m.Client.Do(req)

	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:
		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			return nil, err
		}

		rxRelaxed := xurls.Relaxed()

		unfilteredUrls := rxRelaxed.FindAllString(string(body), -1)

		return filterURLSlice(unfilteredUrls), nil

	default:
		return nil, fmt.Errorf("%w - %v", ErrInvalidStatus, resp.StatusCode)
	}
}

// filterURLSlice removes all unnecessary URls from the
// provided unfilteredUrls parameter and returns a new slice.
func filterURLSlice(unfilteredUrls []string) (filteredUrls []string) {
	for _, urlString := range unfilteredUrls {
		if strings.HasSuffix(urlString, ".js") || strings.HasSuffix(urlString, ".wasm") {
			urlString = strings.TrimSpace(urlString)
			URL, err := url.Parse(urlString)

			if err != nil {
				continue
			}

			if _, ok := URLBlacklist[URL.String()]; ok {
				continue
			}

			if _, ok := HostBlacklist[URL.Hostname()]; ok {
				continue
			}

			filteredUrls = append(filteredUrls, urlString)
		}
	}

	return filteredUrls
}
