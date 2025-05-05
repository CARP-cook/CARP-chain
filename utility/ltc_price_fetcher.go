package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	apiURL           = "https://api.freiexchange.com/public/ticker/VECO"
	envOutputFile    = ".env.ltc_price" // This file can be loaded by the server via godotenv
	defaultCarpQuote = 1000             // Default CARP/VECO rate if env not set
	envVarName       = "CARP_REDEEM_QUOTE_LTC"
	envCarpVeco      = "CARP_REDEEM_QUOTE"
)

type TickerResponse struct {
	VECO_LTC []struct {
		Last string `json:"last"`
	} `json:"VECO_LTC"`
}

func fetchPrice() (float64, error) {
	resp, err := http.Get(apiURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	var data TickerResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, err
	}
	if len(data.VECO_LTC) == 0 {
		return 0, fmt.Errorf("no VECO_LTC data available")
	}
	lastStr := data.VECO_LTC[0].Last
	lastPrice, err := strconv.ParseFloat(lastStr, 64)
	if err != nil {
		return 0, err
	}
	if lastPrice == 0 {
		return 0, fmt.Errorf("last price is zero")
	}
	return lastPrice, nil
}

func writeEnv(ltcQuote int64) error {
	content := fmt.Sprintf("%s=%d\n", envVarName, ltcQuote)
	return os.WriteFile(envOutputFile, []byte(content), 0644)
}

func getCarpVecoRate() int64 {
	val := os.Getenv(envCarpVeco)
	if val == "" {
		return defaultCarpQuote
	}
	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil || v <= 0 {
		return defaultCarpQuote
	}
	return v
}

func main() {
	log.Println("📈 LTC price fetcher started")
	for {
		price, err := fetchPrice()
		if err != nil {
			log.Println("❌ Failed to fetch price:", err)
			time.Sleep(60 * time.Second)
			continue
		}

		carpPerVeco := getCarpVecoRate()
		ltcQuote := int64(math.Round(float64(carpPerVeco) / price))
		log.Printf("🔁 Price fetched: 1 LTC = %.0f VECO → %d CARP\n", 1.0/price, ltcQuote)

		if err := writeEnv(ltcQuote); err != nil {
			log.Println("❌ Failed to write .env file:", err)
		}

		time.Sleep(60 * time.Second)
	}
}
