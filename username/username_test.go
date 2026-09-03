package username_test

import (
	"testing"

	"github.com/go/netbird-pam/api"
	"github.com/go/netbird-pam/username"
)

func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"alice.smith@example.com", "alice-smith"},
		{"first.middle.last@example.com", "first-middle-last"},
		{"alice@example.com", "alice"},
		{"alice@sub.example.com", "alice"},
		{"@example.com", ""},
		{"notanemail", "notanemail"},
	}
	for _, tc := range tests {
		t.Run(tc.email, func(t *testing.T) {
			got := username.SanitizeUsername(tc.email)
			if got != tc.want {
				t.Errorf("sanitizeUsername(%q) = %q, want %q", tc.email, got, tc.want)
			}
		})
	}
}

func TestMatchUser(t *testing.T) {
	users := []api.User{
		{ID: "u1", Email: "alice.smith@example.com"},
		{ID: "u2", Email: "bob@example.com"},
	}
	tests := []struct {
		name          string
		userID        string
		requestedUser string
		want          bool
	}{
		{"exact match with dot conversion", "u1", "alice-smith", true},
		{"exact match no dots", "u2", "bob", true},
		{"wrong username for user", "u1", "alice", false},
		{"impersonation attempt", "u1", "bob", false},
		{"userID not in list", "u99", "alice-smith", false},
		{"empty user list", "", "alice", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := username.MatchUser(users, tc.userID, tc.requestedUser)
			if got != tc.want {
				t.Errorf("matchUser(%q, %q) = %v, want %v", tc.userID, tc.requestedUser, got, tc.want)
			}
		})
	}
}
