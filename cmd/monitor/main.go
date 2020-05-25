package main

import (
	"context"
	"math/rand"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/storage"
)

var wg sync.WaitGroup

func main() {
	rand.Seed(time.Now().UnixNano())

	filepath := os.Getenv("SUP_MONITOR_CONFIG")

	if filepath == "" {
		panic("main: SUP_MONITOR_CONFIG is missing from the environment")
	}

	config, err := readConfig(filepath)

	if err != nil {
		panic(err)
	}

	storageClient, err := storage.NewClient(context.Background())

	if err != nil {
		panic(err)
	}

	for _, siteConfig := range config.Sites {
		monitor, err := createMonitor(&siteConfig, config.WebhookURL, storageClient.Bucket(config.BucketName))

		if err != nil {
			// Handle Error
			continue
		}

		wg.Add(1)

		go func() {
			defer wg.Done()
			monitor.Start()
		}()
	}

	wg.Wait()
}
