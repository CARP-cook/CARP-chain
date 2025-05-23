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
	"time"
)

type Block struct {
	Height    int            `json:"height"`
	Timestamp string         `json:"timestamp"`
	Txs       []app.SignedTx `json:"txs"`
	BlockHash string         `json:"blockhash"`
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/blocks", handleBlocks)
	http.HandleFunc("/blocks/latest", handleLatestBlock)
	http.HandleFunc("/html", handleHTML)
	http.HandleFunc("/", handleHTML)
	fmt.Println("🔍 CARP Explorer available at http://localhost:8081")
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
  background: #0e1a1a;
  font-family: 'Inter', system-ui, sans-serif;
  font-size: 16px;
  color: #d4e9d2;
}

body {
  max-width: 900px;
  margin: 3rem auto;
  padding: 2rem;
  background: #1b2b2b;
  border-radius: 12px;
  box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
}

h1, h2 {
  text-align: center;
  color: #a9d6b4;
  margin-bottom: 1.5rem;
  font-weight: 700;
  text-shadow: 0 1px 2px rgba(0,0,0,0.4);
}

h3 {
  font-size: 1rem;
  color: #e0f2e9;
}

input#searchInput {
  width: 100%;
  padding: 0.8rem;
  border: 1px solid #2e4f4f;
  border-radius: 8px;
  margin-bottom: 1.5rem;
  font-size: 1rem;
  background: #102020;
  color: #e0f2e9;
}

input#searchInput::placeholder {
  color: #b0ccc0;
}

.block {
  background: #162626;
  padding: 1rem;
  border-left: 4px solid #52b788;
  border-radius: 8px;
  margin-bottom: 1rem;
}

.block.highlight {
  background: #1f3a3a;
}

.tx {
  cursor: pointer;
  color: #c3f2d4;
  font-weight: 500;
  margin-left: 1rem;
  margin-top: 0.5rem;
  font-size: 0.95rem;
}

.details {
  display: none;
  background: #213030;
  padding: 0.75rem;
  border-radius: 6px;
  margin: 0.5rem 0 0 2rem;
  font-size: 0.9rem;
  color: #e0f2e9;
}

.details code {
  background: #2a3c3c;
  padding: 2px 5px;
  border-radius: 3px;
  color: #def8e8;
}

.tx code {
  display: block;
  white-space: normal;
  background: #2a3c3c;
  padding: 0.3em 0.5em;
  border-radius: 3px;
  font-size: 0.95em;
  color: #d3f8e2;
}

.pagination {
  margin-top: 2rem;
  text-align: center;
}

.pagination button {
  padding: 0.6rem 1.2rem;
  margin: 0.3rem;
  border: none;
  border-radius: 6px;
  background-color: #74c69d;
  color: #0e1a1a;
  font-weight: bold;
  cursor: pointer;
}

.pagination button:disabled {
  background: #555;
  cursor: not-allowed;
}

code {
  word-break: break-all;
  white-space: normal;
  display: inline-block;
  font-family: monospace;
  background: #2a3c3c;
  padding: 0.2em 0.5em;
  border-radius: 3px;
  font-size: 0.95em;
  max-width: 100%;
  color: #d3f8e2;
}

img {
  max-height: 80px;
  display: block;
  margin: 0 auto 1em auto;
}

@media (max-width: 768px) {
  html {
    font-size: 15px;
  }

  body {
    padding: 1rem;
  }

  h1 {
    font-size: 1.6rem;
    margin-bottom: 1rem;
  }

  input#searchInput {
    font-size: 1rem;
    padding: 0.75rem;
    min-height: 48px;
  }

  .block h3 {
    font-size: 0.95rem;
    word-break: break-word;
  }

  .tx {
    font-size: 0.95rem;
    margin-left: 0.5rem;
    display: block;
    word-wrap: break-word;
  }

  .tx code, .details code {
    font-size: 1rem;
    display: block;
    word-break: break-word;
    white-space: normal;
  }

  .details {
    font-size: 1rem;
    margin-left: 1rem;
  }
}
	  </style>
	  <script>
	    let currentPage = 0;
	    let blocksPerPage = 10;
	    let totalBlocks = 0;
	
	    function toggleDetails(id) {
	      const el = document.getElementById(id);
	      const isHidden = window.getComputedStyle(el).display === "none";
	      el.style.display = isHidden ? "block" : "none";
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
      <img src="/static/carp.png?v={{.Now}}" alt="CARP Logo" />
	  <h1>CARP Explorer</h1>
	  <input type="text" id="searchInput" onkeyup="searchTxs()" placeholder="🔍 Search transactions..." />
	  {{range $i, $block := .Blocks}}
	    <div class="block {{if eq $i 0}}highlight{{end}}">
	      <h3>
  			Block {{$block.Height}} – {{$block.Timestamp}}<br>
		 </h3>
	      {{range $j, $tx := $block.Txs}}
	        <div class="tx" onclick="toggleDetails('tx-{{$block.Height}}-{{$j}}')">
	          ↪ TX: <code>{{$tx.Tx.Hash}}</code>
	        </div>
	        <div class="details" id="tx-{{$block.Height}}-{{$j}}">
	          <div>Type: {{$tx.Tx.Type}}</div>
	          <div>Amount: {{$tx.Tx.Amount}}</div>
	          <div>From: {{$tx.Tx.From}}</div>
	          <div>To: {{$tx.Tx.To}}</div>
	          <div>Nonce: {{$tx.Tx.Nonce}}</div>
	        </div>
	      {{end}}
	    </div>
	  {{end}}
	  <div class="pagination">
	    <button id="prevBtn" onclick="showPage(currentPage - 1)">Previous</button>
	    <button id="nextBtn" onclick="showPage(currentPage + 1)">Next</button>
	  </div>
	</body>
	</html>`
	t := template.Must(template.New("html").Parse(tmpl))
	blocks := loadBlocks(100)
	// Reverse blocks to show the newest block first
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}
	for i := range blocks {
		parsedTime, err := time.Parse(time.RFC3339, blocks[i].Timestamp)
		if err == nil {
			blocks[i].Timestamp = parsedTime.Format("2006-01-02 15:04:05")
		}
	}
	data := struct {
		Now    int64
		Blocks []Block
	}{
		Now:    time.Now().Unix(),
		Blocks: blocks,
	}
	t.Execute(w, data)
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
