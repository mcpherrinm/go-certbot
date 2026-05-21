package verbs

// Revoke uses cfg.Reason (already int after flags.go translation), so
// there's no longer a verb-level lookup function to unit-test here. The
// keyword → code translation is exercised by the flag PostParseHook in
// internal/cmd/flags.go and indirectly covered by the e2e flow.
