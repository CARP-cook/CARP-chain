// utility/explorer.go – simple XuChain block explorer with HTML view
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"xu/app"
)

type Block struct {
	Height    int            `json:"height"`
	Timestamp string         `json:"timestamp"`
	Txs       []app.SignedTx `json:"txs"`
}

func main() {
	http.HandleFunc("/blocks", handleBlocks)
	http.HandleFunc("/blocks/latest", handleLatestBlock)
	http.HandleFunc("/html", handleHTML)
	fmt.Println("🔍 XuChain Block Explorer available at http://localhost:8081")
	http.ListenAndServe(":8081", nil)
}

func handleBlocks(w http.ResponseWriter, r *http.Request) {
	blocks := loadBlocks()
	json.NewEncoder(w).Encode(blocks)
}

func handleLatestBlock(w http.ResponseWriter, r *http.Request) {
	blocks := loadBlocks()
	if len(blocks) == 0 {
		http.Error(w, "No blocks found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(blocks[len(blocks)-1])
}

func handleHTML(w http.ResponseWriter, r *http.Request) {
	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
	  <meta charset="UTF-8">
	  <title>XuChain Explorer</title>
	  <style>body{font-family:sans-serif} .tx{margin-left:1em}</style>
	</head>
	<body>
	  <h1>🧾 XuChain Block Explorer</h1>
	  {{range .}}
	    <h3>🔗 Block {{.Height}} – {{.Timestamp}}</h3>
	    {{range .Txs}}
	      <div class="tx">
	        ↪ <b>{{.Tx.Type}}</b>: {{.Tx.Amount}} Xu from <code>{{.Tx.From}}</code> → <code>{{.Tx.To}}</code> (Nonce: {{.Tx.Nonce}})
	      </div>
	    {{end}}
	  {{end}}
	</body>
	</html>`
	t := template.Must(template.New("html").Parse(tmpl))
	blocks := loadBlocks()
	t.Execute(w, blocks)
}

func loadBlocks() []Block {
	var blocks []Block
	file, err := os.Open("xu_blocks.log")
	if err != nil {
		return blocks
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var b Block
		if err := json.Unmarshal(scanner.Bytes(), &b); err == nil {
			blocks = append(blocks, b)
		}
	}
	return blocks
}
