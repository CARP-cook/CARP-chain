// app.go – CARP Chain application logic with address validation, nonce protection, persistence, and balance access
package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

type SignedTx struct {
	Tx        Tx     `json:"tx"`
	PubKey    string `json:"pubkey"`    // base64 encoded
	Signature string `json:"signature"` // base64 encoded
}

type Tx struct {
	Type   string `json:"type"`
	From   string `json:"from,omitempty"`
	To     string `json:"to"`
	Amount int64  `json:"amount"`
	Nonce  uint64 `json:"nonce"`
	Hash   string `json:"hash"`
}

type CarpApp struct {
	mu     sync.Mutex
	wallet map[string]int64
	nonces map[string]uint64 // nonces[address] = last used nonce
}

func NewCarpApp() *CarpApp {
	app := &CarpApp{
		wallet: make(map[string]int64),
		nonces: make(map[string]uint64),
	}
	app.loadState()
	return app
}

// ApplySignedTxJSON validates and applies a signed transaction
func (a *CarpApp) ApplySignedTxJSON(s SignedTx) ([]byte, error) {
	txBytes, err := CanonicalJSON(s.Tx)
	if err != nil {
		return nil, errors.New("failed to marshal tx")
	}

	pubKeyBytes, err := decodeBase64(s.PubKey)
	if err != nil {
		return nil, errors.New("invalid pubkey")
	}

	if !VerifySignature(txBytes, s.Signature, pubKeyBytes) {
		return nil, errors.New("invalid signature")
	}

	derivedAddr := PublicKeyToAddress(pubKeyBytes)
	if s.Tx.From != "" && s.Tx.From != derivedAddr {
		return nil, fmt.Errorf("sender mismatch: tx.from=%s vs pubkey->addr=%s", s.Tx.From, derivedAddr)
	}

	// Address validation
	if !IsValidAddress(s.Tx.From) && s.Tx.From != "" {
		return nil, fmt.Errorf("invalid sender address format: %s", s.Tx.From)
	}
	if !IsValidAddress(s.Tx.To) && s.Tx.To != "burn" {
		return nil, fmt.Errorf("invalid recipient address format: %s", s.Tx.To)
	}

	// Nonce check
	if s.Tx.Type == "transfer" || strings.HasPrefix(s.Tx.Type, "redeem:") {
		a.mu.Lock()
		lastNonce := a.nonces[s.Tx.From]
		if s.Tx.Nonce <= lastNonce {
			a.mu.Unlock()
			return nil, fmt.Errorf("invalid nonce: %d (last used: %d)", s.Tx.Nonce, lastNonce)
		}
		a.nonces[s.Tx.From] = s.Tx.Nonce
		a.mu.Unlock()
	}

	// Optional: verify tx.Hash
	if s.Tx.Hash != "" {
		expectedHash, err := HashCanonicalTx(s.Tx)
		if err != nil {
			return nil, errors.New("failed to compute tx hash")
		}
		if s.Tx.Hash != expectedHash {
			return nil, fmt.Errorf("tx hash mismatch: expected %s, got %s", expectedHash, s.Tx.Hash)
		}
	}

	res, err := a.ApplyTx(s.Tx)
	if err == nil {
		a.SaveState()
	}
	return res, err
}

// ApplyTx applies a basic (unsigned) transaction
func (a *CarpApp) ApplyTx(tx Tx) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch {
	case tx.Type == "mint":
		a.wallet[tx.To] += tx.Amount
		return []byte(fmt.Sprintf("minted %d CARP to %s", tx.Amount, tx.To)), nil
	case tx.Type == "transfer":
		if a.wallet[tx.From] < tx.Amount {
			return nil, fmt.Errorf("insufficient balance")
		}
		a.wallet[tx.From] -= tx.Amount
		a.wallet[tx.To] += tx.Amount
		return []byte(fmt.Sprintf("transferred %d CARP from %s to %s", tx.Amount, tx.From, tx.To)), nil
	case strings.HasPrefix(tx.Type, "redeem:"):
		if a.wallet[tx.From] < tx.Amount {
			return nil, fmt.Errorf("insufficient balance")
		}
		a.wallet[tx.From] -= tx.Amount
		if tx.To != "burn" {
			a.wallet[tx.To] += tx.Amount
		}
		return []byte(fmt.Sprintf("redeemed %d CARP from %s to %s (redeem target %s)", tx.Amount, tx.From, tx.To, tx.Type[7:])), nil
	default:
		return nil, fmt.Errorf("unknown tx type")
	}
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// IsValidAddress checks if the address matches the expected CARP format
//func IsValidAddress(addr string) bool {
//	matched, _ := regexp.MatchString(`^Ca[a-f0-9]{10}$`, addr)
//	return matched
//}

// IsValidAddress checks both format and checksum of a CARP address (6 byte hash + 2 byte checksum)
func IsValidAddress(addr string) bool {
	if len(addr) != 18 || !strings.HasPrefix(addr, "Ca") {
		return false
	}
	addrHex := addr[2:] // skip "Ca"

	// Decode full address bytes
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil || len(addrBytes) != 8 {
		return false
	}

	core := addrBytes[:6]
	checksum := addrBytes[6:]

	// Recalculate checksum from core hash
	h := sha256.Sum256(core)
	expectedChecksum := h[0:2]

	return checksum[0] == expectedChecksum[0] && checksum[1] == expectedChecksum[1]
}

func (a *CarpApp) SaveState() {
	data := map[string]interface{}{
		"wallet": a.wallet,
		"nonces": a.nonces,
	}
	jsonData, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile("carp_state.json", jsonData, 0644)
}

func (a *CarpApp) LoadState() {
	a.loadState()
}

func (a *CarpApp) loadState() {
	if raw, err := os.ReadFile("carp_state.json"); err == nil {
		var data map[string]json.RawMessage
		if err := json.Unmarshal(raw, &data); err == nil {
			json.Unmarshal(data["wallet"], &a.wallet)
			json.Unmarshal(data["nonces"], &a.nonces)
		}
	}
}

// GetBalance returns the current balance of an address
func (a *CarpApp) GetBalance(addr string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wallet[addr]
}

// GetNonce returns the last used nonce of an address
func (a *CarpApp) GetNonce(addr string) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nonces[addr]
}

// HashCanonicalTx returns the SHA256 hash (hex) of the canonical JSON encoding of a transaction.
func HashCanonicalTx(tx Tx) (string, error) {
	txCopy := tx
	txCopy.Hash = "" // exclude hash from canonical encoding
	data, err := CanonicalJSON(txCopy)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// MustCanonicalJSON returns canonical JSON or panics
func MustCanonicalJSON(tx Tx) []byte {
	data, err := CanonicalJSON(tx)
	if err != nil {
		panic("invalid canonical JSON")
	}
	return data
}

// ComputeTxHash returns the hash of a transaction (used for setting tx.Hash before signing)
func ComputeTxHash(tx Tx) string {
	hash, _ := HashCanonicalTx(tx)
	return hash
}
