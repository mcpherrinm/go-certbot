// Package eff subscribes users to EFF's mailing list at the end of issuance,
// matching certbot/_internal/eff.py.
//
// Behavior:
//   - --eff-email implies subscribe.
//   - --no-eff-email implies skip.
//   - Otherwise: in non-interactive mode, skip; in interactive mode, prompt
//     (interactive prompting is not implemented in Phase 2; we treat the
//     unspecified case as no-op, matching `noninteractive_mode=True`).
package eff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SubscribeURL is the form endpoint Certbot has used for years.
const SubscribeURL = "https://supporters.eff.org/subscribe/certbot"

// Subscribe POSTs the form Certbot does. Returns nil on success; logs but
// does not surface form-level errors (matches Certbot's _report_failure).
func Subscribe(ctx context.Context, email string) error {
	if email == "" {
		return nil
	}
	form := url.Values{
		"data_type": {"json"},
		"email":     {email},
		"form_id":   {"eff_supporters_library_subscribe_form"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, SubscribeURL,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cli := &http.Client{Timeout: 60 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("eff: subscribe POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("eff: subscribe returned %s", resp.Status)
	}
	var body struct {
		Status bool `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil && !body.Status {
		return fmt.Errorf("eff: subscribe rejected (likely invalid email)")
	}
	return nil
}
