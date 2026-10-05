package main

import (
	"context"
	"errors"
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

// apiFailureReason turns a NetBird API error into an audit reason that says
// what to fix: a bad token (401), a token whose role can't read the resource
// (403), or anything else (network, timeout, 5xx).
func apiFailureReason(call string, err error) string {
	if statusErr, ok := errors.AsType[*api.StatusError](err); ok {
		switch statusErr.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Sprintf("netbird-api-unauthorized call=%s hint=%q err=%v", call,
				"NETBIRD_TOKEN was rejected: expired, revoked, or from a different management server", err)
		case http.StatusForbidden:
			return fmt.Sprintf("netbird-api-forbidden call=%s hint=%q err=%v", call,
				"NETBIRD_TOKEN is valid but its role cannot read peers/users", err)
		}
	}
	return fmt.Sprintf("netbird-api-failed call=%s err=%v", call, err)
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
	if err != nil {
		return audit(false, sourceIP, requestedUser, apiFailureReason("fetch-peers", err))
	}
	if len(peers) == 0 {
		return audit(false, sourceIP, requestedUser, "no-peer-found")
	}

	userID := peers[0].UserID
	if userID == "" {
		return audit(false, sourceIP, requestedUser, "peer-has-no-user-id")
	}

	users, err := apiClient.FetchUsers(ctx)
	if err != nil {
		return audit(false, sourceIP, requestedUser, apiFailureReason("fetch-users", err))
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
