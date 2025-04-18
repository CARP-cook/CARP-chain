// main.go – XuChain mit Mempool (Soft-Limit pro Absender) & Lazy Block-Produktion
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "sync"
    "time"

    "xu/app"
)

var mempool []app.SignedTx
var mempoolMu sync.Mutex
const maxTxPerSender = 5

func main() {
    fmt.Println("🟢 XuChain Sequencer mit Mempool gestartet (30s Lazy Blocks)")

    xuApp := app.NewXuApp()

    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    blockHeight := 1

    go listenForTxs()

    for {
        <-ticker.C
        mempoolMu.Lock()
        if len(mempool) > 0 {
            fmt.Printf("\n⛓️  Block %d erzeugt (%d TXs)\n", blockHeight, len(mempool))
            for _, tx := range mempool {
                res, err := xuApp.ApplySignedTxJSON(tx)
                if err != nil {
                    fmt.Println("🚫 TX Fehler:", err)
                } else {
                    fmt.Println("✅ TX OK:", string(res))
                }
            }
            mempool = nil
            blockHeight++
        } else {
            fmt.Printf("\n⏳ Block %d übersprungen (kein TX)\n", blockHeight)
        }
        mempoolMu.Unlock()
    }
}

func listenForTxs() {
    decoder := json.NewDecoder(os.Stdin)
    for {
        var tx app.SignedTx
        if err := decoder.Decode(&tx); err == nil {
            mempoolMu.Lock()
            sender := tx.Tx.From
            if countTxsFrom(sender) >= maxTxPerSender {
                fmt.Printf("⚠️  TX von %s abgelehnt: Soft-Limit (%d) erreicht\n", sender, maxTxPerSender)
            } else {
                mempool = append(mempool, tx)
                fmt.Printf("📥 TX empfangen von %s → %s (%d Xu)\n", sender, tx.Tx.To, tx.Tx.Amount)
            }
            mempoolMu.Unlock()
        }
        time.Sleep(100 * time.Millisecond)
    }
}

func countTxsFrom(addr string) int {
    count := 0
    for _, tx := range mempool {
        if tx.Tx.From == addr {
            count++
        }
    }
    return count
}
