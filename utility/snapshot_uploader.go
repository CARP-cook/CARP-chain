// snapshot_uploader.go – Upload carp_blocks.log.gz snapshot to GitHub
package main

import (
	"bytes"
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
	repoOwner = "CARP-cook"
	repoName  = "CARP-snapshots"
	branch    = "main"
)

var filePath string

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Println("❌ GITHUB_TOKEN not set")
		os.Exit(1)
	}

	fileData, _, err := readStateFile()
	if err != nil {
		fmt.Println("❌ Reading state file failed:", err)
		os.Exit(1)
	}

	filePath = "carp_state.json"

	b64Content := base64.StdEncoding.EncodeToString(fileData)

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

func readStateFile() ([]byte, string, error) {
	data, err := os.ReadFile("carp_state.json")
	if err != nil {
		return nil, "", err
	}
	return data, "carp_state.json", nil
}
