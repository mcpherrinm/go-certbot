// Package parser implements a minimal, hand-rolled nginx configuration
// parser. It targets the dialect Certbot operates on: simple directives,
// block directives (http/server/location/upstream/etc.), quoted/unquoted
// arguments, and `# ...` line comments. It deliberately doesn't try to
// understand Lua extensions, `if` semantics, or `include` resolution depth
// limits — see CHANGES.md for the scope and known unsupported constructs.
//
// The parser preserves leading whitespace (indentation, blank lines) and
// comments so a write-back round-trip lands close to the original file.
package parser

import (
	"fmt"
	"strings"
	"unicode"
)

// token is a single lexical unit. Kind discriminates; Value is the raw text
// (including quotes for QuotedString); Whitespace is the run of spaces, tabs,
// and newlines that immediately preceded the token (preserved for re-emit).
type token struct {
	Kind       tokenKind
	Value      string
	Whitespace string
}

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokWord
	tokQuotedString // "..." or '...' (Value INCLUDES the quotes)
	tokOpenBrace    // {
	tokCloseBrace   // }
	tokSemicolon    // ;
	tokComment      // # ... (Value INCLUDES the leading #, not newline)
)

func (k tokenKind) String() string {
	switch k {
	case tokEOF:
		return "EOF"
	case tokWord:
		return "word"
	case tokQuotedString:
		return "quoted-string"
	case tokOpenBrace:
		return "{"
	case tokCloseBrace:
		return "}"
	case tokSemicolon:
		return ";"
	case tokComment:
		return "comment"
	}
	return "?"
}

// lexer is a simple character-level scanner.
type lexer struct {
	src string
	pos int
}

func newLexer(src string) *lexer { return &lexer{src: src} }

// next returns the next token, or {Kind: tokEOF} at end of input.
func (l *lexer) next() (token, error) {
	ws := l.consumeWhitespace()
	if l.pos >= len(l.src) {
		return token{Kind: tokEOF, Whitespace: ws}, nil
	}
	c := l.src[l.pos]
	switch c {
	case '{':
		l.pos++
		return token{Kind: tokOpenBrace, Value: "{", Whitespace: ws}, nil
	case '}':
		l.pos++
		return token{Kind: tokCloseBrace, Value: "}", Whitespace: ws}, nil
	case ';':
		l.pos++
		return token{Kind: tokSemicolon, Value: ";", Whitespace: ws}, nil
	case '#':
		return token{Kind: tokComment, Value: l.consumeUntilNewline(), Whitespace: ws}, nil
	case '"', '\'':
		val, err := l.consumeQuoted(c)
		if err != nil {
			return token{}, err
		}
		return token{Kind: tokQuotedString, Value: val, Whitespace: ws}, nil
	}
	return token{Kind: tokWord, Value: l.consumeWord(), Whitespace: ws}, nil
}

func (l *lexer) consumeWhitespace() string {
	start := l.pos
	for l.pos < len(l.src) {
		c := rune(l.src[l.pos])
		if !unicode.IsSpace(c) {
			break
		}
		l.pos++
	}
	return l.src[start:l.pos]
}

func (l *lexer) consumeUntilNewline() string {
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.pos++
	}
	return l.src[start:l.pos]
}

func (l *lexer) consumeQuoted(quote byte) (string, error) {
	start := l.pos
	l.pos++ // opening quote
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '\\' && l.pos+1 < len(l.src) {
			l.pos += 2
			continue
		}
		if c == quote {
			l.pos++ // closing quote
			return l.src[start:l.pos], nil
		}
		l.pos++
	}
	return "", fmt.Errorf("nginx: unterminated quoted string at offset %d", start)
}

// consumeWord reads characters until whitespace, ';', '{', '}', or '#' (comment).
// Allows `=`, `~`, regex constructs, paths, IPs, etc.
func (l *lexer) consumeWord() string {
	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if unicode.IsSpace(rune(c)) ||
			c == ';' || c == '{' || c == '}' || c == '#' {
			break
		}
		l.pos++
	}
	if l.pos == start {
		// Should not happen — caller already checked specials.
		l.pos++
	}
	return strings.TrimSpace(l.src[start:l.pos])
}
