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
	SHA     string `json:"sha,omitempty"`
	Branch  string `json:"branch,omitempty"`
}

type GitHubResponse struct {
	SHA     string          `json:"sha"`
	Content json.RawMessage `json:"content"`
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
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", repoOwner, repoName, filePath)

	sha, err := getExistingFileSHA(url, token)
	if err != nil {
		fmt.Println("❌ Failed to get existing file SHA:", err)
		os.Exit(1)
	}

	// Optional: Skip upload if identical
	existingContent, err := fetchFileContentFromGitHub(url, token)
	if err == nil && bytes.Equal(existingContent, fileData) {
		fmt.Println("✅ Snapshot identical — skipping upload.")
		return
	}

	payload := GitHubRequest{
		Message: fmt.Sprintf("Snapshot upload %s", time.Now().Format(time.RFC3339)),
		Content: b64Content,
		SHA:     sha,
		Branch:  branch,
	}

	data, _ := json.Marshal(payload)

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

func getExistingFileSHA(url, token string) (string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// file does not exist yet
		return "", nil
	} else if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
	}

	var res GitHubResponse
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return "", err
	}

	return res.SHA, nil
}

func readStateFile() ([]byte, string, error) {
	data, err := os.ReadFile("carp_state.json")
	if err != nil {
		return nil, "", err
	}
	return data, "carp_state.json", nil
}

func fetchFileContentFromGitHub(url, token string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var response struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	if response.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding: %s", response.Encoding)
	}

	decoded, err := base64.StdEncoding.DecodeString(response.Content)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}
