package identity

import (
	"context"
	"errors"
	"fmt"
)

// Preferences are how a person likes every t10 app to look. An empty field means
// they haven't chosen.
type Preferences struct {
	Language string `json:"language,omitempty"`
	Theme    string `json:"theme,omitempty"`
}

// ErrInvalidPreference is a language or theme no app knows.
var ErrInvalidPreference = errors.New("invalid preference")

func validPreferences(p Preferences) bool {
	switch p.Language {
	case "", "en", "zh-Hans":
	default:
		return false
	}
	switch p.Theme {
	case "", "system", "light", "dark":
	default:
		return false
	}
	return true
}

// GetPreferences reads a person's language and theme.
func (s *Service) GetPreferences(ctx context.Context, userID string) (Preferences, error) {
	var p Preferences
	err := s.pool.QueryRow(ctx, "SELECT language, theme FROM auth.users WHERE id = $1", userID).Scan(&p.Language, &p.Theme)
	if err != nil {
		return Preferences{}, fmt.Errorf("read preferences: %w", err)
	}
	return p, nil
}

// SetPreferences changes the fields given and keeps the rest. They aren't audited:
// how a page looks grants nothing.
func (s *Service) SetPreferences(ctx context.Context, userID string, change Preferences) (Preferences, error) {
	if !validPreferences(change) {
		return Preferences{}, ErrInvalidPreference
	}
	var p Preferences
	err := s.pool.QueryRow(ctx, `UPDATE auth.users
		SET language = CASE WHEN $2 = '' THEN language ELSE $2 END,
		    theme = CASE WHEN $3 = '' THEN theme ELSE $3 END
		WHERE id = $1
		RETURNING language, theme`, userID, change.Language, change.Theme).Scan(&p.Language, &p.Theme)
	if err != nil {
		return Preferences{}, fmt.Errorf("update preferences: %w", err)
	}
	return p, nil
}
