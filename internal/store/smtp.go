package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host                string `json:"host"`
	Port                int    `json:"port"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	From                string `json:"from"`
	To                  string `json:"to"`
	ThresholdDays       int    `json:"threshold_days"`
	CheckIntervalHours  int    `json:"check_interval_hours"`
	Enabled             bool   `json:"enabled"`
}

// LoadSMTPConfig reads data/smtp.json. Returns a zero-value config (not an
// error) if the file does not yet exist.
func LoadSMTPConfig(dataDir string) (SMTPConfig, error) {
	path := filepath.Join(dataDir, "smtp.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SMTPConfig{ThresholdDays: 30}, nil
		}
		return SMTPConfig{}, err
	}

	var cfg SMTPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return SMTPConfig{}, err
	}
	if cfg.ThresholdDays == 0 {
		cfg.ThresholdDays = 30
	}
	return cfg, nil
}

// SaveSMTPConfig writes cfg to data/smtp.json (0644).
func SaveSMTPConfig(dataDir string, cfg SMTPConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, "smtp.json")
	return os.WriteFile(path, data, 0o644)
}

// LoadNotifyLastRun reads the timestamp of the last notification check from
// data/notify_last_run. Returns zero time (not an error) if the file doesn't exist.
func LoadNotifyLastRun(dataDir string) (time.Time, error) {
	path := filepath.Join(dataDir, "notify_last_run")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// SaveNotifyLastRun writes the current time to data/notify_last_run.
func SaveNotifyLastRun(dataDir string, t time.Time) error {
	path := filepath.Join(dataDir, "notify_last_run")
	return os.WriteFile(path, []byte(t.UTC().Format(time.RFC3339)), 0o644)
}
