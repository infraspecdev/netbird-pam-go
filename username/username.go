package username

import (
	"strings"

	"github.com/go/netbird-pam/api"
)

func SanitizeUsername(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return strings.ReplaceAll(local, ".", "-")
}

func MatchUser(users []api.User, userID, requestedUser string) (string, bool) {
	for _, u := range users {
		if u.ID == userID {
			matchedUser := SanitizeUsername(u.Email)
			return matchedUser, matchedUser == requestedUser
		}
	}
	return "", false
}
