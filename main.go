package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"os"
	"strings"
	"time"
)

// set via -ldflags at build time
var (
	netbirdToken  string
	netbirdAPI    string
	netbirdPrefix string
)

const (
	pamSuccess = 0
	pamDeny    = 1
)

type Peer struct {
	ID     string `json:"id"`
	IP     string `json:"ip"`
	UserID string `json:"user_id"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

var logger *syslog.Writer

func initLogger() {
	var err error
	logger, err = syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "netbird-pam")
	if err != nil {
		fmt.Fprintln(os.Stderr, "netbird-pam: syslog unavailable:", err)
		os.Exit(pamSuccess)
	}
}

func logf(priority syslog.Priority, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	switch priority {
	case syslog.LOG_WARNING:
		logger.Warning(msg)
	case syslog.LOG_ERR:
		logger.Err(msg)
	default:
		logger.Info(msg)
	}
}

func apiGet(path string, out any) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", netbirdAPI+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+netbirdToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, out)
}

func sanitizeUsername(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return strings.ReplaceAll(local, ".", "-")
}

func main() {
	initLogger()

	sourceIP := os.Getenv("PAM_RHOST")
	requestedUser := os.Getenv("PAM_USER")

	if !strings.HasPrefix(sourceIP, netbirdPrefix) {
		logf(syslog.LOG_INFO, "non-netbird source %q, skipping", sourceIP)
		os.Exit(pamSuccess)
	}

	var peers []Peer
	if err := apiGet("/api/peers?ip="+sourceIP, &peers); err != nil {
		logf(syslog.LOG_ERR, "peers fetch failed: %v, denying", err)
		os.Exit(pamDeny)
	}

	if len(peers) == 0 {
		logf(syslog.LOG_WARNING, "no peer for IP %s, denying", sourceIP)
		os.Exit(pamDeny)
	}

	userID := peers[0].UserID
	if userID == "" {
		logf(syslog.LOG_WARNING, "peer at %s has no user_id, denying", sourceIP)
		os.Exit(pamDeny)
	}

	var users []User
	if err := apiGet("/api/users", &users); err != nil {
		logf(syslog.LOG_ERR, "users fetch failed: %v, denying", err)
		os.Exit(pamDeny)
	}

	for _, u := range users {
		if u.ID == userID {
			derived := sanitizeUsername(u.Email)
			if derived == requestedUser {
				logf(syslog.LOG_INFO, "allowed %s from %s", requestedUser, sourceIP)
				os.Exit(pamSuccess)
			}
			logf(syslog.LOG_WARNING, "denied: requested=%s derived=%s from %s", requestedUser, derived, sourceIP)
			os.Exit(pamDeny)
		}
	}

	logf(syslog.LOG_WARNING, "user_id %s not found, denying", userID)
	os.Exit(pamDeny)
}
