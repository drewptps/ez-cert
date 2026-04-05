package store

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func AuthHashExists(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, "auth.hash"))
	return err == nil
}

func LoadAuthHash(dataDir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dataDir, "auth.hash"))
}

func WriteAuthHash(dataDir string, hash []byte) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, "auth.hash"), hash, 0o600)
}

func AppendAuditLog(dataDir, event string) error {
	path := filepath.Join(dataDir, "audit.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line := time.Now().UTC().Format("2006-01-02T15:04:05Z") + "  " + event + "\n"
	_, err = f.WriteString(line)
	return err
}

func LoadAuditLogLines(dataDir string) ([]string, error) {
	path := filepath.Join(dataDir, "audit.log")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Reverse for newest-first.
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	return lines, nil
}
