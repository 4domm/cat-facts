package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type MeowFactResponse struct {
	Data []string `json:"data"`
}

func main() {
	url := "https://meowfacts.herokuapp.com/"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch data: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	var meowFactResponse MeowFactResponse
	if err := json.Unmarshal(body, &meowFactResponse); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}
	for _, fact := range meowFactResponse.Data {
		fmt.Printf("Cat Fact: %s\n", fact)
	}
}
