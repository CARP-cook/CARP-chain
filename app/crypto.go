// crypto.go – CARP Chain cryptographic utilities (key generation, signing, verification)
package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// GenerateKeyPair returns a new ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return pub, priv
}

// PublicKeyToAddress generates a CARP address from the given public key.
func PublicKeyToAddress(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "Ca" + hex.EncodeToString(h[:])[:10] // short address prefix
}

// Sign signs the given transaction bytes with the provided private key and returns a base64-encoded signature.
func Sign(txBytes []byte, priv ed25519.PrivateKey) string {
	sig := ed25519.Sign(priv, txBytes)
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifySignature checks whether the base64-encoded signature is valid for the given transaction bytes and public key.
func VerifySignature(txBytes []byte, sigB64 string, pub ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, txBytes, sig)
}

// VerifySignatureRaw checks whether the given signature is valid for the txBytes and public key.
func VerifySignatureRaw(txBytes []byte, sig []byte, pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, txBytes, sig)
}

// CanonicalJSON returns deterministic JSON bytes for any given value.
// It marshals the input, unmarshals into a generic map, sorts keys, and re-marshals deterministically.
func CanonicalJSON(v any) ([]byte, error) {
	// Marshal original struct
	tmp, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Decode into generic interface{}
	var obj interface{}
	if err := json.Unmarshal(tmp, &obj); err != nil {
		return nil, err
	}

	// Normalize
	normalized, err := normalize(obj)
	if err != nil {
		return nil, err
	}

	// Encode back deterministically
	buf := new(bytes.Buffer)
	if err := encodeCanonicalJSON(buf, normalized); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normalize walks the data and ensures all maps are sorted consistently
func normalize(v interface{}) (interface{}, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		// Sort keys
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// Normalize values
		normalized := make([][2]interface{}, 0, len(keys))
		for _, k := range keys {
			normVal, err := normalize(val[k])
			if err != nil {
				return nil, err
			}
			normalized = append(normalized, [2]interface{}{k, normVal})
		}
		return normalized, nil
	case []interface{}:
		normalized := make([]interface{}, len(val))
		for i, item := range val {
			normItem, err := normalize(item)
			if err != nil {
				return nil, err
			}
			normalized[i] = normItem
		}
		return normalized, nil
	default:
		return val, nil
	}
}

// encodeCanonicalJSON writes normalized data in deterministic JSON format
func encodeCanonicalJSON(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case [][2]interface{}: // normalized map
		buf.WriteByte('{')
		for i, pair := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyBytes, _ := json.Marshal(pair[0])
			valBuf := new(bytes.Buffer)
			encodeCanonicalJSON(valBuf, pair[1])
			buf.Write(keyBytes)
			buf.WriteByte(':')
			buf.Write(valBuf.Bytes())
		}
		buf.WriteByte('}')
	case []interface{}: // list
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeCanonicalJSON(buf, elem)
		}
		buf.WriteByte(']')
	default:
		raw, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(raw)
	}
	return nil
}

// SignCanonical signs the canonical JSON representation of v and returns a base64 signature.
func SignCanonical(v any, priv ed25519.PrivateKey) (string, error) {
	data, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyCanonicalSignature verifies the base64 signature against the canonical JSON of v.
func VerifyCanonicalSignature(v any, sigB64 string, pub ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	data, err := CanonicalJSON(v)
	if err != nil {
		return false
	}
	fmt.Println("🛂 Canonical JSON on server:\n", string(data))
	return ed25519.Verify(pub, data, sig)
}
