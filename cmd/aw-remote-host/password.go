package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// generatePassword returns a random 32-hex-char (16-byte) secret — used
// once to set the local Postgres superuser password on first bootstrap,
// then persisted in state.json so re-runs reuse it instead of locking
// themselves out of the existing data volume.
func generatePassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return hex.EncodeToString(b), nil
}
