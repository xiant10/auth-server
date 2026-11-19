package identity

import (
	"fmt"
	"slices"
	"strings"
)

// Languages are the ones every t10 app is written in, in the order a choice shows
// them. A deployment may offer fewer: see ParseLanguages.
var Languages = []string{"en", "zh-Hans"}

// ParseLanguages reads AUTH_LANGUAGES, the languages a deployment offers, comma
// separated, its default first. Empty offers them all.
func ParseLanguages(list string) ([]string, error) {
	if strings.TrimSpace(list) == "" {
		return slices.Clone(Languages), nil
	}
	var offered []string
	for part := range strings.SplitSeq(list, ",") {
		lang := strings.TrimSpace(part)
		if !slices.Contains(Languages, lang) {
			return nil, fmt.Errorf("unknown language %q: t10 has %s", lang, strings.Join(Languages, ", "))
		}
		if slices.Contains(offered, lang) {
			return nil, fmt.Errorf("language %q is listed twice", lang)
		}
		offered = append(offered, lang)
	}
	return offered, nil
}

// Languages are the ones this deployment offers, its default first.
func (s *Service) Languages() []string { return slices.Clone(s.languages) }

// effectiveLanguage is the language a person's apps show: the one they chose, if
// it's still offered. With one language there is nothing to choose. Otherwise ""
// means they haven't chosen, and an app shows the browser's language if it's offered.
func (s *Service) effectiveLanguage(saved string) string {
	switch {
	case slices.Contains(s.languages, saved):
		return saved
	case len(s.languages) == 1:
		return s.languages[0]
	}
	return ""
}
