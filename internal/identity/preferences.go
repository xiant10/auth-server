package identity

import (
	"context"
	"errors"
	"fmt"
)

// Preferences are how a person likes every t10 app to look and greet them. An empty
// field means they haven't chosen.
type Preferences struct {
	Language string `json:"language,omitempty"`
	Theme    string `json:"theme,omitempty"`
	// Greeting is how an agent greets them when they start a call: personal,
	// simple or off. See agent-ti's docs/greeting.md.
	Greeting string `json:"greeting,omitempty"`
}

// ErrInvalidPreference is a language, theme or greeting no app knows.
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
	switch p.Greeting {
	case "", "personal", "simple", "off":
	default:
		return false
	}
	return true
}

// GetPreferences reads a person's language, theme and greeting.
func (s *Service) GetPreferences(ctx context.Context, userID string) (Preferences, error) {
	var p Preferences
	err := s.pool.QueryRow(ctx, "SELECT language, theme, greeting FROM auth.users WHERE id = $1", userID).Scan(&p.Language, &p.Theme, &p.Greeting)
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
		    theme = CASE WHEN $3 = '' THEN theme ELSE $3 END,
		    greeting = CASE WHEN $4 = '' THEN greeting ELSE $4 END
		WHERE id = $1
		RETURNING language, theme, greeting`, userID, change.Language, change.Theme, change.Greeting).Scan(&p.Language, &p.Theme, &p.Greeting)
	if err != nil {
		return Preferences{}, fmt.Errorf("update preferences: %w", err)
	}
	return p, nil
}
