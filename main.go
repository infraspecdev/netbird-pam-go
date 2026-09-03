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
	netbirdPrefix = "100."
	pamSuccess    = 0
	pamDeny       = 1
)

var logger *syslog.Writer

func initLogger() {
	var err error
	logger, err = syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "netbird-pam")
	if err != nil {
		os.Exit(pamSuccess)
	}
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

	if !strings.HasPrefix(sourceIP, netbirdPrefix) {
		logger.Info("non-netbird source, allowing")
		return pamSuccess
	}

	token, mgmtURL, err := loadConfig()
	if err != nil {
		logger.Err("config load failed, denying: " + err.Error())
		return pamDeny
	}

	apiClient := api.NewClient(client, mgmtURL, token)

	peers, err := apiClient.FetchPeers(ctx, sourceIP)
	if err != nil || len(peers) == 0 {
		logger.Warning("no peer found for IP, denying")
		return pamDeny
	}

	userID := peers[0].UserID
	if userID == "" {
		logger.Warning("peer has no user_id, denying")
		return pamDeny
	}

	users, err := apiClient.FetchUsers(ctx)
	if err != nil {
		logger.Err("users fetch failed, denying")
		return pamDeny
	}

	if !username.MatchUser(users, userID, requestedUser) {
		logger.Warning("username match failed, denying")
		return pamDeny
	}

	logger.Info("allowed " + requestedUser + " from " + sourceIP)
	return pamSuccess
}

func main() {
	initLogger()
	client := &http.Client{Timeout: 5 * time.Second}
	os.Exit(Authorize(os.Getenv("PAM_RHOST"), os.Getenv("PAM_USER"), client))
}
