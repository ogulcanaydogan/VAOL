// Example: Direct VAOL server interaction in Go.
//
// Demonstrates appending a DecisionRecord, retrieving it,
// verifying the DSSE envelope, and exporting an audit bundle.
//
// Usage:
//
//	go run main.go
//
// Requires a running VAOL server at http://localhost:8080
// with --auth-mode disabled --policy-mode allow-all.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

const baseURL = "http://localhost:8080"

func main() {
	// 1. Build a DecisionRecord
	record := map[string]any{
		"schema_version": "v1",
		"request_id":     uuid.New().String(),
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"identity": map[string]any{
			"tenant_id":    "example-org",
			"subject":      "demo-user",
			"subject_type": "user",
		},
		"model": map[string]any{
			"provider": "openai",
			"name":     "gpt-4o",
			"version":  "2025-01-01",
		},
		"parameters": map[string]any{
			"temperature": 0.7,
			"max_tokens":  1024,
		},
		"prompt_context": map[string]any{
			"user_prompt_hash":   sha256Hash("What is the capital of France?"),
			"system_prompt_hash": sha256Hash("You are a helpful assistant."),
			"message_count":      2,
		},
		"policy_context": map[string]any{
			"policy_decision": "allow",
		},
		"output": map[string]any{
			"output_hash":   sha256Hash("The capital of France is Paris."),
			"mode":          "hash_only",
			"output_tokens": 8,
			"finish_reason": "stop",
			"latency_ms":    245.3,
		},
		"trace":     map[string]any{},
		"integrity": map[string]any{},
	}

	fmt.Println("=== VAOL Go Example ===")
	fmt.Println()

	// 2. Append the record
	fmt.Println("1. Appending DecisionRecord...")
	receipt := post("/v1/records", record)
	fmt.Printf("   Record stored: request_id=%s sequence=%v\n\n",
		receipt["request_id"], receipt["sequence_number"])

	// 3. Retrieve it
	fmt.Println("2. Retrieving record...")
	requestID := receipt["request_id"].(string)
	stored := get(fmt.Sprintf("/v1/records/%s", requestID))
	fmt.Printf("   Retrieved: tenant=%s model=%s\n\n",
		dig(stored, "record", "identity", "tenant_id"),
		dig(stored, "record", "model", "name"))

	// 4. Verify the envelope
	fmt.Println("3. Verifying DSSE envelope...")
	envelope := stored["envelope"]
	result := post("/v1/verify", envelope)
	fmt.Printf("   Valid: %v\n", result["valid"])
	if checks, ok := result["checks"].([]any); ok {
		for _, c := range checks {
			check := c.(map[string]any)
			status := "PASS"
			if check["passed"] != true {
				status = "FAIL"
			}
			fmt.Printf("   - %s: %s\n", check["name"], status)
		}
	}
	fmt.Println()

	// 5. Get Merkle proof
	fmt.Println("4. Fetching Merkle inclusion proof...")
	proof := get(fmt.Sprintf("/v1/records/%s/proof", requestID))
	fmt.Printf("   Tree size: %v  Leaf index: %v\n\n",
		proof["tree_size"], proof["leaf_index"])

	// 6. Get checkpoint
	fmt.Println("5. Fetching latest checkpoint...")
	checkpoint := get("/v1/ledger/checkpoint")
	fmt.Printf("   Root: %s\n   Tree size: %v\n\n",
		checkpoint["root_hash"], checkpoint["tree_size"])

	// 7. Export bundle
	fmt.Println("6. Exporting audit bundle...")
	bundle := post("/v1/export", map[string]any{
		"tenant_id": "example-org",
	})
	if records, ok := bundle["records"].([]any); ok {
		fmt.Printf("   Bundle contains %d record(s)\n", len(records))
	}

	fmt.Println("\nDone.")
}

func sha256Hash(data string) string {
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("sha256:%x", h)
}

func post(path string, body any) map[string]any {
	data, err := json.Marshal(body)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(baseURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	return readJSON(resp, path)
}

func get(path string) map[string]any {
	resp, err := http.Get(baseURL + path)
	if err != nil {
		log.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	return readJSON(resp, path)
}

func readJSON(resp *http.Response, path string) map[string]any {
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "ERROR %s %d: %s\n", path, resp.StatusCode, body)
		os.Exit(1)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("unmarshal %s: %v\nbody: %s", path, err, body)
	}
	return result
}

func dig(m map[string]any, keys ...string) any {
	var current any = m
	for _, k := range keys {
		cm, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = cm[k]
	}
	return current
}
