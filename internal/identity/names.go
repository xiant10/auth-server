package identity

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nyaruka/phonenumbers"
)

// Kinds of sign-in name.
const (
	KindUsername = "username"
	KindPhone    = "phone"
	KindEmail    = "email"
)

// ErrInvalidName means a sign-in name matches no accepted format.
var ErrInvalidName = errors.New("invalid sign-in name")

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

const maxDisplayName = 100

// cleanDisplayName trims a name for teammates to see. Empty passes, because a
// mobile client may register before asking for one.
func cleanDisplayName(input string) (string, error) {
	name := strings.TrimSpace(input)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxDisplayName || strings.ContainsFunc(name, unicode.IsControl) {
		return "", ErrInvalidDisplayName
	}
	return name, nil
}

// NormalizeName classifies a sign-in name and returns its stored form. The
// three formats cannot overlap: only an email contains @, only a phone number
// starts with + or a digit, and a username starts with a letter. region is the
// default for phone numbers with no country code.
func NormalizeName(input, region string) (kind, value string, err error) {
	name := strings.TrimSpace(input)
	if name == "" {
		return "", "", ErrInvalidName
	}
	if strings.Contains(name, "@") {
		local, domain, ok := strings.Cut(strings.ToLower(name), "@")
		if !ok || local == "" || domain == "" || strings.ContainsAny(name, " \t\r\n") || strings.Contains(domain, "@") {
			return "", "", ErrInvalidName
		}
		return KindEmail, local + "@" + domain, nil
	}
	if first := name[0]; first == '+' || (first >= '0' && first <= '9') {
		number, err := phonenumbers.Parse(name, region)
		if err != nil || !phonenumbers.IsValidNumber(number) {
			return "", "", ErrInvalidName
		}
		return KindPhone, phonenumbers.Format(number, phonenumbers.E164), nil
	}
	lower := strings.ToLower(name)
	if !usernamePattern.MatchString(lower) {
		return "", "", ErrInvalidName
	}
	return KindUsername, lower, nil
}
