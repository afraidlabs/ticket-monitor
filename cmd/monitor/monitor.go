package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"

	"mvdan.cc/xurls/v2"
)

// Monitor is an instance of a monitor which scans for changes
// from the specified SiteConfig.
type Monitor struct {
	// Mutex exists to prevent data races
	// on the FileHashes
	Mutex sync.Mutex

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
}

// ScanURL is a struct of a URL found by the parser.
// It contains a depth limit, which prevents scanning
// too far.
type ScanURL struct {
	// URL is the URL of the file as string.
	URL string

	// GroupTag helps group together files
	// from Supreme's website.
	GroupTag string

	// ScanDepth is the depth limit left based
	// on this ScanURL.
	ScanDepth uint8
}

// File is a struct contains parameters
// of a file and its origin.
type File struct {
	// URL is the URL the file was located on.
	URL *url.URL

	// Bytes is the source of the file that
	// was found.
	Bytes []byte

	// Hash is the hash of the file with the
	// SHAKE-256 algorithm.
	Hash string

	// GroupTag helps group together files
	// from Supreme's website.
	GroupTag string

	// ResponseHeader contains a slice of
	// headers sent from the server, they may
	// be used in preventing bots so a log is saved.
	ResponseHeader http.Header
}

var (
	// ErrInvalidURL occurs when no URL is specified
	ErrInvalidURL = errors.New("monitor: no url specified")

	// ErrInvalidWebhookURL occurs when no URL is specified
	ErrInvalidWebhookURL = errors.New("monitor: no webhookUrl specified")

	// ErrInvalidStatus occurs when a response's status is not 200 OK
	ErrInvalidStatus = errors.New("monitor: invalid response status code")

	// ForbiddenUrls contains a list of URLs to ignore in the monitor
	ForbiddenUrls = map[string]bool{
		"google-analytics.com/ga.js": true,
	}

	// ForbiddenHosts contains a list of hostnames to ignore in the monitor
	ForbiddenHosts = map[string]bool{
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
	urlChannel := make(chan *ScanURL)

	// Start 20 goroutines to process multiple files concurrently
	// without leaking goroutines.
	for i := 0; i < 10; i++ {
		go m.ProcessFiles(fileChannel)
		go m.ProcessScanUrls(urlChannel, fileChannel)
	}

	for {
		groupTag := uuid.New().String()
		urls, err := m.Get(m.SiteConfig.URL, fileChannel, groupTag)

		if err != nil {
			// Handle Error
			time.Sleep(time.Duration(m.SiteConfig.Delay) * time.Millisecond)
			continue
		}

		for _, url := range urls {
			urlChannel <- &ScanURL{
				URL:       url,
				GroupTag:  groupTag,
				ScanDepth: m.SiteConfig.ScanDepth,
			}
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
			file.Hash = hex.EncodeToString(hashBytes[:])
			if _, exists := m.FileHashes[file.Hash]; !exists {
				m.Mutex.Lock()
				m.FileHashes[file.Hash] = true
				m.Mutex.Unlock()

				for i := 0; i < 5; i++ {
					err := m.UploadFile(file)

					if err == nil {
						return
					}
					// Handle Error
					fmt.Println(err)
				}

			}
		}
	}
}

// UploadFile takes a file that doesnt already exist
// and uploads to your Google CLoud Storage Bucket.
func (m *Monitor) UploadFile(file *File) error {
	fmt.Printf("Found new file - %v - %v\n", file.URL.String(), file.Hash)

	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)

	if err != nil {
		return err
	}

	basePath := path.Base(file.URL.Path)
	name := fmt.Sprintf("%s/%s/%s_%s", time.Now().Format(time.RFC3339), file.GroupTag, hex.EncodeToString(randomBytes), basePath)
	object := m.Bucket.Object(name)

	w := object.NewWriter(context.Background())

	_, err = w.Write(file.Bytes)
	if err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	metadata := map[string]string{
		"x-fm-file-url":   file.URL.String(),
		"x-fm-shake-256":  file.Hash,
		"x-fm-timestamp":  time.Now().Format(time.RFC3339Nano),
		"x-fm-proxy-url":  m.SiteConfig.ProxyURL,
		"x-fm-user-agent": m.Header.Get("User-Agent"),
	}

	if len(file.ResponseHeader) > 0 {
		bytes, err := json.Marshal(&file.ResponseHeader)
		if err == nil {
			metadata["x-fm-response-headers"] = string(bytes)
		} else {
			metadata["x-fm-response-headers-error"] = err.Error()

		}
	}

	uattrs := storage.ObjectAttrsToUpdate{
		Metadata: metadata,
	}

	_, err = object.Update(context.Background(), uattrs)
	if err != nil {
		return err
	}

	fmt.Printf("Wrote File - %s\n", object.ObjectName())
	return nil
}

// ProcessScanUrls receives URL strings to scan from a channel and attempts to
// retrieve any URLs found in the file. If there are any URLs and the ScanDepth
// is more than zero, it will queue more URLs to scan.
func (m *Monitor) ProcessScanUrls(urlChannel chan *ScanURL, fileChannel chan<- *File) {
	for scanURL := range urlChannel {
		urls, err := m.Get(scanURL.URL, fileChannel, scanURL.GroupTag)

		if err != nil {
			// Handle Error
			fmt.Println(err)
			continue
		}

		if scanURL.ScanDepth > 0 {
			for _, url := range urls {
				urlChannel <- &ScanURL{
					URL:       url,
					GroupTag:  scanURL.GroupTag,
					ScanDepth: scanURL.ScanDepth - 1,
				}
			}
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
			URL:            resp.Request.URL,
			Bytes:          body,
			GroupTag:       groupTag,
			ResponseHeader: resp.Header,
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
		if strings.HasSuffix(rawurl, ".js") || strings.HasSuffix(rawurl, ".wasm") || strings.HasSuffix(rawurl, ".css") {
			URL, err := url.Parse(rawurl)

			if err != nil {
				continue
			}

			if _, ok := ForbiddenUrls[URL.String()]; ok {
				continue
			}

			if _, ok := ForbiddenHosts[URL.Hostname()]; ok {
				continue
			}

			filteredUrls = append(filteredUrls, rawurl)
		}
	}

	return filteredUrls
}
