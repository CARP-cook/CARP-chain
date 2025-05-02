// utility/explorer.go – simple CARP Chain block explorer with HTML view
package main

import (
	"bufio"
	"carp/app"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
)

type Block struct {
	Height    int            `json:"height"`
	Timestamp string         `json:"timestamp"`
	Txs       []app.SignedTx `json:"txs"`
	BlockHash string         `json:"blockhash"`
}

func main() {
	http.HandleFunc("/blocks", handleBlocks)
	http.HandleFunc("/blocks/latest", handleLatestBlock)
	http.HandleFunc("/html", handleHTML)
	fmt.Println("🔍 CARP Chain Block Explorer available at http://localhost:8081")
	http.ListenAndServe(":8081", nil)
}

func handleBlocks(w http.ResponseWriter, r *http.Request) {
	blocks := loadBlocks(0)
	json.NewEncoder(w).Encode(blocks)
}

func handleLatestBlock(w http.ResponseWriter, r *http.Request) {
	blocks := loadBlocks(0)
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
	  <title> CARP Chain Explorer</title>
	  <style>
	  html {
	    background: linear-gradient(to bottom, #d9f2e6, #e0dcbf);
	  }
	  *, *::before, *::after {
	    box-sizing: border-box;
	  }
	  body {
	    font-family: 'Georgia', serif;
	    max-width: 800px;
	    margin: auto;
	    padding: 2em;
	    background-color: #ffffff;
	    color: #2e4d2c;
	    box-shadow: 0 0 15px rgba(0, 0, 0, 0.2);
	    border-radius: 10px;
	    background-image: url('/carp_bg.png');
	    background-size: contain;
	    background-repeat: no-repeat;
	    background-position: center top;
	  }
	  .tx {
	    margin-left: 2em;
	    cursor: pointer;
	    color: #356a3a;
	    text-decoration: underline;
	  }
	  .details {
	    display: none;
	    margin-left: 3em;
	    font-size: 0.9em;
	    background: #f0fff0;
	    padding: 0.5em;
	    border-left: 4px solid #a2c48c;
	    border-radius: 4px;
	  }
	  .highlight {
	    background-color: #ffeeba;
	  }
	  .pagination {
	    margin-top: 1em;
	    text-align: center;
	  }
	  .pagination button {
	    margin: 0.3em;
	    padding: 0.6em 1.2em;
	    background-color: #a2c48c;
	    font-weight: bold;
	    border: none;
	    border-radius: 5px;
	  }
	  .pagination button:hover {
	    background-color: #89b46a;
	    cursor: pointer;
	  }
	  #searchInput {
	    width: 100%;
	    margin-bottom: 1em;
	    padding: 0.7em;
	    border: 1px solid #6b8e23;
	    background: #f9fff9;
	    font-family: 'Georgia', serif;
	    font-size: 1em;
	    border-radius: 6px;
	  }
	  h1 {
	    font-family: 'Georgia', serif;
	    color: #3a5d30;
	    text-shadow: 1px 1px 2px #cde3c5;
	    text-align: center;
	  }
	  h3 {
	    margin-top: 1.2em;
	    color: #355835;
	  }
	  code {
	    background-color: #eef7e9;
	    padding: 0.2em 0.4em;
	    border-radius: 3px;
	    font-weight: bold;
	  }
	  </style>
	  <script>
	    let currentPage = 0;
	    let blocksPerPage = 10;
	    let totalBlocks = 0;
	
	    function toggleDetails(id) {
	      const el = document.getElementById(id);
	      el.style.display = el.style.display === "none" ? "block" : "none";
	    }
	
	    function showPage(page) {
	      const all = document.querySelectorAll('.block');
	      for (let i = 0; i < all.length; i++) {
	        all[i].style.display = (i >= page * blocksPerPage && i < (page + 1) * blocksPerPage) ? "block" : "none";
	      }
	      currentPage = page;
	      updateButtons();
	    }
	
	    function updateButtons() {
	      document.getElementById("prevBtn").disabled = currentPage === 0;
	      document.getElementById("nextBtn").disabled = ((currentPage + 1) * blocksPerPage) >= totalBlocks;
	    }
	
	    function searchTxs() {
	      const query = document.getElementById("searchInput").value.toLowerCase();
	      const blocks = document.querySelectorAll(".block");

	      blocks.forEach(block => {
	        const heightText = block.querySelector("h3").textContent.toLowerCase();
	        const txsText = block.textContent.toLowerCase();
	        const isMatch = heightText.includes(query) || txsText.includes(query);
	        block.style.display = isMatch ? "block" : "none";

	        const txDivs = block.querySelectorAll(".tx, .details");
	        txDivs.forEach(div => {
	          div.style.display = isMatch ? "block" : "none";
	        });
	      });
	    }
	
	    window.onload = () => {
	      totalBlocks = document.querySelectorAll('.block').length;
	      showPage(0);
	    };
	  </script>
	</head>
	<body>
	  <h1>🧾 CARP Chain Block Explorer</h1>
	  <input type="text" id="searchInput" onkeyup="searchTxs()" placeholder="🔍 Search transactions..." />
	  {{range $i, $block := .}}
	    <div class="block {{if eq $i 0}}highlight{{end}}">
	      <h3>🔗 Block {{$block.Height}} – {{$block.Timestamp}} – <code>{{$block.BlockHash}}</code></h3>
	      {{range $j, $tx := $block.Txs}}
	        <div class="tx" onclick="toggleDetails('tx-{{$block.Height}}-{{$j}}')">
	          ↪ TX: <code>{{$tx.Tx.Hash}}</code>
	        </div>
	        <div class="details" id="tx-{{$block.Height}}-{{$j}}">
	          <div>Type: {{$tx.Tx.Type}}</div>
	          <div>Amount: {{$tx.Tx.Amount}}</div>
	          <div>From: <code>{{$tx.Tx.From}}</code></div>
	          <div>To: <code>{{$tx.Tx.To}}</code></div>
	          <div>Nonce: {{$tx.Tx.Nonce}}</div>
	        </div>
	      {{end}}
	    </div>
	  {{end}}
	  <div class="pagination">
	    <button id="prevBtn" onclick="showPage(currentPage - 1)">⬅️ Previous</button>
	    <button id="nextBtn" onclick="showPage(currentPage + 1)">Next ➡️</button>
	  </div>
	</body>
	</html>`
	t := template.Must(template.New("html").Parse(tmpl))
	blocks := loadBlocks(100)
	// Reverse blocks to show the newest block first
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}
	t.Execute(w, blocks)
}

func loadBlocks(limit int) []Block {
	var blocks []Block
	files, err := filepath.Glob("blocks/*.log")
	if err != nil {
		fmt.Println("⚠️ Failed to scan blocks/:", err)
		return blocks
	}
	sort.Strings(files)

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var b Block
			if err := json.Unmarshal(scanner.Bytes(), &b); err == nil {
				blocks = append(blocks, b)
			}
		}
		f.Close()
	}

	if limit > 0 && len(blocks) > limit {
		return blocks[len(blocks)-limit:]
	}
	return blocks
}
