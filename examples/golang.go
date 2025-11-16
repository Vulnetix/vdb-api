// VDB API Testing - AWS SigV4 Authentication Example (Go)
// This example uses AWS SDK for Go v2
//
// Install dependencies:
// go get github.com/aws/aws-sdk-go-v2/aws
// go get github.com/aws/aws-sdk-go-v2/aws/signer/v4
// go get github.com/aws/aws-sdk-go-v2/config

package main

import (
    "bytes"
    "context"
    "crypto/sha512"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Step 1: Configuration - Set your Organization credentials
const (
    VVD_ORG    = "f7c11fc1-d422-4242-a05e-ea3e747b07bc" // Organization UUID (used as access key)
    VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs" // Organization Secret (64 chars)
    VVD_ACCESS_KEY = VVD_ORG // Access key is the Organization UUID
)

// Static credentials provider for VDB API
type staticCredentialsProvider struct {
    accessKey string
    secretKey string
}

func (s *staticCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
    return aws.Credentials{
        AccessKeyID:     s.accessKey,
        SecretAccessKey: s.secretKey,
    }, nil
}

// Step 2: Hash function for SHA-512 payload hashing
func sha512Hash(data []byte) string {
    hash := sha512.Sum512(data)
    return hex.EncodeToString(hash[:])
}

// Step 3: Get JWT token from /v1/auth/token using AWS SigV4
func getJWTToken() (string, error) {
    ctx := context.Background()
    url := "https://api.vdb.vulnetix.com/v1/auth/token"

    // Create HTTP request
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return "", fmt.Errorf("failed to create request: %w", err)
    }

    // Create credentials provider
    credsProvider := &staticCredentialsProvider{
        accessKey: VVD_ACCESS_KEY,
        secretKey: VVD_SECRET,
    }

    // Retrieve credentials
    creds, err := credsProvider.Retrieve(ctx)
    if err != nil {
        return "", fmt.Errorf("failed to retrieve credentials: %w", err)
    }

    // Create AWS SigV4 signer
    signer := v4.NewSigner()

    // Calculate payload hash (empty body)
    payloadHash := sha512Hash([]byte(""))

    // Sign the request with SigV4
    err = signer.SignHTTP(ctx, creds, req, payloadHash, "vdb", "us-east-1", time.Now())
    if err != nil {
        return "", fmt.Errorf("failed to sign request: %w", err)
    }

    // Execute the request
    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return "", fmt.Errorf("failed to execute request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response: %w", err)
    }

    // Check status code
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
    }

    // Parse JSON response
    var result struct {
        Token string `json:"token"`
        Iss   string `json:"iss"`
        Sub   string `json:"sub"`
        Exp   int64  `json:"exp"`
    }

    if err := json.Unmarshal(body, &result); err != nil {
        return "", fmt.Errorf("failed to parse response: %w", err)
    }

    fmt.Printf("JWT token obtained (expires in 15 minutes): %s...\n", result.Token[:50])
    fmt.Printf("Token details:\n")
    fmt.Printf("  iss: %s\n", result.Iss)
    fmt.Printf("  sub: %s\n", result.Sub)
    fmt.Printf("  exp: %s\n", time.Unix(result.Exp, 0).Format(time.RFC3339))

    return result.Token, nil
}

// Step 4: Make authenticated API request
func makeAPIRequest(jwtToken string) error {
    url := "https://api.vdb.vulnetix.com/v1/ecosystems"

    // Create HTTP request
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    // Add Authorization header with JWT token
    req.Header.Set("Authorization", "Bearer "+jwtToken)
    req.Header.Set("Content-Type", "application/json")

    // Execute the request
    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("failed to execute request: %w", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response: %w", err)
    }

    // Pretty print JSON response
    var prettyJSON bytes.Buffer
    if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
        fmt.Printf("API Response (raw): %s\n", string(body))
    } else {
        fmt.Printf("API Response:\n%s\n", prettyJSON.String())
    }

    return nil
}

// Main function
func main() {
    // Step 1: Get JWT token
    jwtToken, err := getJWTToken()
    if err != nil {
        fmt.Printf("Error getting JWT token: %v\n", err)
        return
    }

    // Step 2: Make API request
    if err := makeAPIRequest(jwtToken); err != nil {
        fmt.Printf("Error making API request: %v\n", err)
        return
    }
}
