package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestCleanDisplayName(t *testing.T) {
	for input, want := range map[string]string{
		"  Ada L  ":              "Ada L",
		"":                       "",
		"李雷":                     "李雷",
		strings.Repeat("字", 100): strings.Repeat("字", 100),
	} {
		if got, err := cleanDisplayName(input); err != nil || got != want {
			t.Errorf("%q = %q, %v", input, got, err)
		}
	}
	// Form posts can carry any bytes, and Postgres refuses invalid UTF-8.
	for _, input := range []string{"a\xffb", "a\nb", "a\x00b", strings.Repeat("x", 101)} {
		if _, err := cleanDisplayName(input); !errors.Is(err, ErrInvalidDisplayName) {
			t.Errorf("%q: err = %v", input, err)
		}
	}
}
