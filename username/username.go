package username

import (
	"strings"

	"github.com/go/netbird-pam/api"
)

func SanitizeUsername(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return strings.ReplaceAll(local, ".", "-")
}

func MatchUser(users []api.User, userID, requestedUser string) bool {
	for _, u := range users {
		if u.ID == userID {
			return SanitizeUsername(u.Email) == requestedUser
		}
	}
	return false
}
