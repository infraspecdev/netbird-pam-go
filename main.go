package main

import (
	"context"
	"fmt"
	"log/syslog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go/netbird-pam/api"
	"github.com/go/netbird-pam/username"
	"github.com/joho/godotenv"
)

var configPath = "/etc/netbird-pam/config.env"

const (
	pamSuccess = 0
	pamDeny    = 1
)

var netbirdPrefixes = []string{
	"100.99.",
	"fdc1:f44a:39d9:c331:",
}

func isNetbirdSource(sourceIP string) bool {
	for _, prefix := range netbirdPrefixes {
		if strings.HasPrefix(sourceIP, prefix) {
			return true
		}
	}
	return false
}

var logger *syslog.Writer

func initLogger() {
	var err error
	logger, err = syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "netbird-pam")
	if err != nil {
		os.Exit(pamSuccess)
	}
}

func authLogMessage(allowed bool, sourceIP, requestedUser, reason string) string {
	decision := "allowing"
	if !allowed {
		decision = "denying"
	}
	return fmt.Sprintf("%s: sourceIP=%s requestedUser=%s reason=%s", decision, sourceIP, requestedUser, reason)
}

func audit(allowed bool, sourceIP, requestedUser, reason string) int {
	msg := authLogMessage(allowed, sourceIP, requestedUser, reason)

	if allowed {
		logger.Info(msg)
		return pamSuccess
	}
	logger.Warning(msg)
	return pamDeny
}

func loadConfig() (token, mgmtURL string, err error) {
	if err = godotenv.Load(configPath); err != nil {
		return
	}
	token = os.Getenv("NETBIRD_TOKEN")
	mgmtURL = os.Getenv("NETBIRD_MANAGEMENT_URL")
	if token == "" || mgmtURL == "" {
		err = fmt.Errorf("missing NETBIRD_TOKEN or NETBIRD_MANAGEMENT_URL")
	}
	return
}

func Authorize(sourceIP, requestedUser string, client *http.Client) int {
	ctx := context.Background()

	if !isNetbirdSource(sourceIP) {
		return audit(true, sourceIP, requestedUser, "non-netbird-source")
	}

	token, mgmtURL, err := loadConfig()
	if err != nil {
		return audit(false, sourceIP, requestedUser, fmt.Sprintf("config-load-failed err=%v", err))
	}

	apiClient := api.NewClient(client, mgmtURL, token)

	peers, err := apiClient.FetchPeers(ctx, sourceIP)
	if err != nil || len(peers) == 0 {
		return audit(false, sourceIP, requestedUser, fmt.Sprintf("no-peer-found err=%v", err))
	}

	userID := peers[0].UserID
	if userID == "" {
		return audit(false, sourceIP, requestedUser, "peer-has-no-user-id")
	}

	users, err := apiClient.FetchUsers(ctx)
	if err != nil {
		return audit(false, sourceIP, requestedUser, fmt.Sprintf("users-fetch-failed err=%v", err))
	}

	matchedUser, ok := username.MatchUser(users, userID, requestedUser)
	if !ok {
		return audit(false, sourceIP, requestedUser, fmt.Sprintf("username-mismatch matchedUser=%q", matchedUser))
	}

	return audit(true, sourceIP, requestedUser, fmt.Sprintf("username-matched-netbird-peer matchedUser=%q", matchedUser))
}

func main() {
	initLogger()
	client := &http.Client{Timeout: 5 * time.Second}
	os.Exit(Authorize(os.Getenv("PAM_RHOST"), os.Getenv("PAM_USER"), client))
}
