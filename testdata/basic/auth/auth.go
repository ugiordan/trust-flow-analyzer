package auth

import "errors"

func ValidateToken(token string) (string, error) {
	if token == "" {
		return "", errors.New("empty token")
	}
	return "user@example.com", nil
}

func Authorize(user string, groups []string) bool {
	if len(groups) == 0 {
		return true
	}
	for _, g := range groups {
		if g == "admin" {
			return true
		}
	}
	return false
}

func CheckGroups(user string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	return false
}
