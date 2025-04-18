// wallet.go – simple CLI tool to generate a new XuChain wallet
package main

import (
	"encoding/base64"
	"fmt"
	"xu/app"
)

func main() {
	pub, priv := app.GenerateKeyPair()
	addr := app.PublicKeyToAddress(pub)

	fmt.Println("🔐 New wallet key generated:")
	fmt.Println("Address :", addr)
	fmt.Println("Public  :", base64.StdEncoding.EncodeToString(pub))
	fmt.Println("Private :", base64.StdEncoding.EncodeToString(priv))
}
