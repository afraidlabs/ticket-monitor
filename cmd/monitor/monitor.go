package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/uuid"

	"golang.org/x/crypto/sha3"
	"mvdan.cc/xurls/v2"
)

// Monitor is an instance of a monitor which scans for changes
// from the specified SiteConfig.
type Monitor struct {
	// Bucket is a Google Cloud Storage
	// Bucket where files will be saved.
	Bucket *storage.BucketHandle

	// Client carries out all requests for the
	// monitor instance.
	Client *http.Client

	// Header is a http.Header struct using the
	// specified Headers in the SiteConfig
	Header http.Header

	// SiteConfig are the parameters for monitoring
	// Supreme's website.
	SiteConfig *SiteConfig

	// WebhookURL is a Discord Webhook URL where
	// updates on site changes will be sent.
	// It is a required field.
	WebhookURL string

	// FileHashes is makeshift Set which contains
	// all previously detected files.
	FileHashes map[string]bool

	// StorageClient is a Google Cloud Storage
	// Client where files will be archived.
	StorageClient *storage.Client
}

// File is a struct contains parameters
// of a file and its origin.
type File struct {
	// URL is the URL the file was located on.
	URL *url.URL

	// Bytes is the source of the file that
	// was found.
	Bytes []byte

	// GroupTag helps group together files
	// on Supreme's website.
	GroupTag string
}

var (
	// ErrInvalidURL occurs when no URL is specified
	ErrInvalidURL = errors.New("monitor: no url specified")

	// ErrInvalidWebhookURL occurs when no URL is specified
	ErrInvalidWebhookURL = errors.New("monitor: no webhookUrl specified")

	// ErrInvalidStatus occurs when a response's status is not 200 OK
	ErrInvalidStatus = errors.New("monitor: invalid response status code")

	// URLBlacklist contains a list of URLs to ignore in the monitor
	URLBlacklist = map[string]bool{
		"google-analytics.com/ga.js": true,
	}

	// HostBlacklist contains a list of hostnames to ignore in the monitor
	HostBlacklist = map[string]bool{
		"cdn.mxpnl.com":                 true,
		"www.google.com":                true,
		"songbird.cardinalcommerce.com": true,
	}
)

// createMonitor creates a Monitor with the supplied siteConfig
// parameter. If it fails an error is returned.
func createMonitor(siteConfig *SiteConfig, webhookURL string, bucket *storage.BucketHandle) (*Monitor, error) {
	if siteConfig.URL == "" {
		return nil, ErrInvalidURL
	}

	if webhookURL == "" {
		return nil, ErrInvalidWebhookURL
	}

	header := http.Header{}

	for key, value := range siteConfig.Headers {
		header.Set(key, value)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
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
		Bucket:     bucket,
		Client:     client,
		Header:     header,
		SiteConfig: siteConfig,
		WebhookURL: webhookURL,
		FileHashes: make(map[string]bool),
	}, nil
}

// Start starts the infinite loop of monitoring from the URL specified
// in the SiteConfig
func (m *Monitor) Start() {
	fileChannel := make(chan *File)

	go m.ProcessFiles(fileChannel)

	for {
		groupTag := uuid.New().String()
		urls, err := m.Get(m.SiteConfig.URL, fileChannel, groupTag)
		if err != nil {
			// Handle Error
			time.Sleep(time.Duration(m.SiteConfig.Delay) * time.Millisecond)
			continue
		}

		for _, url := range urls {
			go m.ScanURL(url, fileChannel, groupTag, m.SiteConfig.ScanDepth)
		}

		time.Sleep(time.Duration(m.SiteConfig.Delay) * time.Millisecond)
	}
}

// ProcessFiles processes incoming files from
// the specified fileChannel channel parameter
func (m *Monitor) ProcessFiles(fileChannel <-chan *File) {
	for file := range fileChannel {
		if file != nil {
			hashBytes := sha3.Sum256(file.Bytes)
			hash := hex.EncodeToString(hashBytes[:])
			if _, exists := m.FileHashes[hash]; !exists {
				fmt.Printf("Found new file - %v - %v\n", file.URL.String(), hash)

				basePath := path.Base(file.URL.Path)
				name := fmt.Sprintf("%v/%v/%v", time.Now().Format(time.RFC1123), file.GroupTag, basePath)
				object := m.Bucket.Object(name)

				w := object.NewWriter(context.Background())

				w.ObjectAttrs = storage.ObjectAttrs{
					Name: name,
					Metadata: map[string]string{
						"shake-256":  hash,
						"timestamp":  time.Now().Format(time.RFC3339Nano),
						"proxy-url":  m.SiteConfig.ProxyURL,
						"user-agent": m.Header.Get("User-Agent"),
					},
				}

				_, err := w.Write(file.Bytes)
				if err != nil {
					// Handle Error
					fmt.Println(err)
					continue
				}

				if err := w.Close(); err != nil {
					fmt.Println(err)
					continue
				}

				m.FileHashes[hash] = true

				fmt.Printf("Wrote File - %v - %v\n", basePath, hash)
			}
		}
	}
}

// ScanURL goes deeper into each url specified.
// If scanDepth is more than zero it recurses
// till scanDepth reaches zero.
func (m *Monitor) ScanURL(url string, fileChannel chan<- *File, groupTag string, scanDepth uint8) {
	urls, err := m.Get(url, fileChannel, groupTag)

	if err != nil {
		// Handle Error
		fmt.Println(err)
		return
	}

	if scanDepth > 0 {
		for _, url := range urls {
			go m.ScanURL(url, fileChannel, groupTag, scanDepth-1)
		}
	}
}

// Get uses the URL specified in the function parameters
// gather the set of URLs. If it fails an error is returned.
func (m *Monitor) Get(rawurl string, fileChannel chan<- *File, groupTag string) ([]string, error) {
	url, err := url.Parse(rawurl)

	if err != nil {
		return nil, err
	}

	if url.Scheme == "" {
		url.Scheme = "https"
	}

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)

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

		fileChannel <- &File{
			URL:      resp.Request.URL,
			Bytes:    body,
			GroupTag: groupTag,
		}

		bodyString := string(body)

		rxRelaxed := xurls.Relaxed()

		unfilteredUrls := rxRelaxed.FindAllString(bodyString, -1)

		return filterURLSlice(unfilteredUrls), nil

	default:
		return nil, fmt.Errorf("%w - %v", ErrInvalidStatus, resp.StatusCode)
	}
}

// filterURLSlice removes all unnecessary URls from the
// provided unfilteredUrls parameter and returns a new slice.
func filterURLSlice(unfilteredUrls []string) (filteredUrls []string) {
	for _, rawurl := range unfilteredUrls {
		if strings.HasSuffix(rawurl, ".js") || strings.HasSuffix(rawurl, ".wasm") {
			rawurl = strings.TrimSpace(rawurl)
			URL, err := url.Parse(rawurl)

			if err != nil {
				continue
			}

			if _, ok := URLBlacklist[URL.String()]; ok {
				continue
			}

			if _, ok := HostBlacklist[URL.Hostname()]; ok {
				continue
			}

			filteredUrls = append(filteredUrls, rawurl)
		}
	}

	return filteredUrls
}
