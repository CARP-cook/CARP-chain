// crypto.go – XuChain cryptographic utilities (key generation, signing, verification)
package app

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
)

// GenerateKeyPair returns a new ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
    pub, priv, _ := ed25519.GenerateKey(nil)
    return pub, priv
}

// PublicKeyToAddress generates a Xu address from the given public key.
func PublicKeyToAddress(pub ed25519.PublicKey) string {
    h := sha256.Sum256(pub)
    return "Xu" + hex.EncodeToString(h[:])[:10] // short address prefix
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

