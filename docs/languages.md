---
title: "Languages: per deployment, chosen on the account page"
audience: contributor
kind: design
status: current
summary: "A deployment may fix the languages t10 offers (AUTH_LANGUAGES); a person chooses language and theme only on the account page, and every web app follows them."
---

# Languages

Nov 18, 2026 · Status: built across `auth-server`, `t10-modkit` (copied into every consumer by the workspace's `scripts/sync-modkit.sh`), `workbench`, `t10-property`, `t10-console` and `t10-quickstart`. Decided Nov 18: the signed-out pages keep a switch that changes only those pages; theme moves to the account page with language; a person who never chose sees the browser's language when it's offered.

## What it does

1. **A deployment can fix its languages.** `AUTH_LANGUAGES` is a comma-separated list, the default first. `zh-Hans` gives everyone Simplified Chinese and no choice anywhere. `zh-Hans,en` offers both, Chinese the default. Unset offers every language t10 has (`en,zh-Hans`). An unknown or repeated tag stops auth-server at start.
2. **A person chooses language and theme in one place:** the "Language and theme" card on the account page's Profile tab. With one language offered, the card shows it as text, "Set for this deployment". No other page or app draws a switch for either.
3. **Every web app follows.** Workbench, Property, the console and auth-server's own pages show the account's choice. Someone who hasn't chosen sees the browser's language if it's offered, else the deployment's default.

## How

### auth-server

- `identity.Languages` is every language the apps are written in; `identity.ParseLanguages` reads `AUTH_LANGUAGES`, and `Options.Languages` gives the service the list.
- `GET /v1/me/preferences` (and the service route `/v1/users/{id}/preferences`) answers the effective `language` and the offered `languages`:

  ```json
  { "language": "zh-Hans", "theme": "dark", "languages": ["zh-Hans"] }
  ```

  A saved language that's offered is the answer. With one language offered, that one is, for everyone. Otherwise a saved language no longer offered reads as no choice. The stored value is kept, so offering it again gives it back.
- `PUT /v1/me/preferences` refuses a language not offered (`400`). It stays for API clients; no web app calls it.
- **Pages.** The route guard gives every page request the offered list and, on a signed-in page, the account's language, which wins over the `t10_locale` cookie and `Accept-Language`. Signed-in pages draw no switch. Signed-out pages draw `POST /v1/language` only when more than one language is offered, and it sets `t10_locale` for this browser's signed-out pages and saves nothing.
- **Sign-in.** `/v1/authorize` hands the app `lang` only when the person chose one on the account page. Nothing at sign-in saves a language any more (`t10_locale_chosen` is gone), so a browser's guess never becomes a choice.
- **Account page.** `POST /v1/account` takes `action=language` with `lang`, and `action=theme` with `theme`. A language change redraws the answer in it at once and sets `t10_locale`. `POST /v1/theme` is gone.

### t10-modkit

- Go `frame.Menu` lost `Lang`, `Here`, `LanguageAction` and `ThemeAction`: the account menu on server-drawn pages is Account and Sign out.
- Web kit: `AccountMenu` has no language or theme field, and `LanguageSwitch` is gone. `useI18n()` has no `setLanguage`; only `useSavedPreferences` changes the language (`useApplyLanguage`) and theme (`applySavedTheme`), from what auth-server answers, when a page opens and whenever it's shown again. The offered list is cached (`wb:languages`) so the first paint guesses within it.

### Apps

- Workbench and Property: `PUT /api/preferences` is gone; `GET` passes the answer through. Their palettes lost the theme and language commands; Workbench already has "Account", and Property gained one. Workbench's signed-out screens lost their switch.
- Console: the language comes from the person's preferences, with `t10_locale` and `Accept-Language` as fallbacks within the offered list. Its `/language` and `/theme` handlers and the switch on its centre pages are gone. It caches a person's frame for 60 seconds, so a change on the account page shows there within a minute; the web apps show it when the tab is next focused.

### Deploying

- k8s: set `AUTH_LANGUAGES` in the `auth-server` ConfigMap of an overlay. The base leaves it unset.
- `t10-quickstart`: `T10_LANGUAGES=zh-Hans` in `.env` sets it.

## Not in this change

- **Mobile and Mac clients.** `flutter` keeps its own language and doesn't read preferences. It should read `language` and `languages` from `/v1/me/preferences` the same way and drop its in-app choice.
- **Agent replies.** Agents answer in the language people write in. The call greeting reads the effective language, so it follows the limit.
- **A third language** is a catalog per app plus a tag in `identity.Languages` (and the kit's `LANGUAGES`).
