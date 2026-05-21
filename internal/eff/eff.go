// Package eff subscribes users to EFF's mailing list at the end of issuance,
// matching certbot/_internal/eff.py.
//
// Behavior:
//   - --eff-email implies subscribe (errors are non-fatal).
//   - --no-eff-email implies skip.
//   - Otherwise: in non-interactive mode skip, else prompt.
//
// Failures are NON-fatal per Certbot's _report_failure semantics — we
// notify the user via stdout with the standard "act.eff.org" suggestion
// and never return errors to callers.
package eff

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/letsencrypt/go-certbot/internal/config"
	"github.com/letsencrypt/go-certbot/internal/display"
)

// SubscribeURL is the form endpoint Certbot has used for years.
const SubscribeURL = "https://supporters.eff.org/subscribe/certbot"

// reportFailure is Certbot's canonical wording (eff.py:_report_failure).
const reportFailure = "We were unable to subscribe you the EFF mailing list because your e-mail address appears to be invalid. You can try again later by visiting https://act.eff.org."

// Decide returns true if Certbot would subscribe the user to the EFF
// mailing list. Reads cfg.EFFEmail (tri-state), prompts interactively
// when unset and stdin is a TTY.
func Decide(cfg *config.Config) bool {
	if cfg.EFFEmail != nil {
		return *cfg.EFFEmail
	}
	if cfg.NoEFFEmail {
		return false
	}
	if cfg.NonInteractive {
		return false
	}
	if cfg.Email == "" {
		return false
	}
	// Interactive prompt — matches Certbot's _want_subscription
	// (eff.py:63-76). Default No: respect privacy unless user explicitly
	// opts in.
	prompt := "Would you be willing, once your first certificate is successfully issued, " +
		"to share your email address with the Electronic Frontier Foundation, " +
		"a founding partner of the Let's Encrypt project and the non-profit " +
		"organization that develops Certbot? We'd like to send you email about " +
		"our work encrypting the web, EFF news, campaigns, and ways to support " +
		"digital freedom."
	return display.YesNoDefault(prompt, false)
}

// Subscribe POSTs the form Certbot does. Errors are non-fatal: callers
// can ignore the returned bool — true means "succeeded", false means
// "soft failure was already reported to the user".
func Subscribe(ctx context.Context, email string) bool {
	if email == "" {
		// Certbot's _report_failure path triggers here too — we asked to
		// subscribe but have no address.
		display.Notify(reportFailure)
		return false
	}
	form := url.Values{
		"data_type": {"json"},
		"email":     {email},
		"form_id":   {"eff_supporters_library_subscribe_form"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, SubscribeURL,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		display.Notify(reportFailure)
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Certbot's eff.py:91 uses requests.post with no custom UA — the
	// default requests UA suffices. Mirror by not overriding.
	cli := &http.Client{Timeout: 60 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		display.Notify(reportFailure)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		display.Notify(reportFailure)
		return false
	}
	var body struct {
		Status bool `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil && !body.Status {
		display.Notify(reportFailure)
		return false
	}
	return true
}
