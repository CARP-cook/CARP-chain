// snapshot_uploader.go – Upload carp_blocks.log.gz snapshot to GitHub
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type GitHubRequest struct {
	Message string `json:"message"`
	Content string `json:"content"`
	Branch  string `json:"branch,omitempty"`
}

type GitHubResponse struct {
	Content struct {
		SHA string `json:"sha"`
	} `json:"content"`
	SHA string `json:"sha"`
}

const (
	repoOwner = "tedydet"
	repoName  = "xu-chain-backup-test"
	branch    = "main"
)

var filePath string

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Println("❌ GITHUB_TOKEN not set")
		os.Exit(1)
	}

	compressedData, filename, err := compressLatestBlockFile()
	if err != nil {
		fmt.Println("❌ Compression failed:", err)
		os.Exit(1)
	}

	filePath = filepath.Base(filename)

	b64Content := base64.StdEncoding.EncodeToString(compressedData)

	payload := GitHubRequest{
		Message: fmt.Sprintf("Snapshot upload %s", time.Now().Format(time.RFC3339)),
		Content: b64Content,
		Branch:  branch,
	}

	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", repoOwner, repoName, filePath)

	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("❌ Upload failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		fmt.Println("✅ Snapshot uploaded successfully!")
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("❌ GitHub error (%d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}
}

func compressLatestBlockFile() ([]byte, string, error) {
	files, err := filepath.Glob("carp_blocks_*.log")
	if err != nil || len(files) == 0 {
		return nil, "", fmt.Errorf("no block files found")
	}

	sort.Strings(files)
	latest := files[len(files)-1]

	f, err := os.Open(latest)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err = io.Copy(gz, f)
	if err != nil {
		gz.Close()
		return nil, "", err
	}
	gz.Close()
	return buf.Bytes(), latest + ".gz", nil
}
