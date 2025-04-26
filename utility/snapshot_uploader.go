// snapshot_uploader.go – Upload xu_blocks.log.gz snapshot to GitHub
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
	filePath  = "xu_blocks.log.gz" // compressed snapshot
	branch    = "main"
)

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Println("❌ GITHUB_TOKEN not set")
		os.Exit(1)
	}

	compressedData, err := compressFile("xu_blocks.log")
	if err != nil {
		fmt.Println("❌ Compression failed:", err)
		os.Exit(1)
	}

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

func compressFile(filename string) ([]byte, error) {
	in, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err = io.Copy(gz, in)
	gz.Close()

	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
