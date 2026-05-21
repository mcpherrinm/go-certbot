// Package parser implements a minimal, hand-rolled Apache httpd configuration
// parser. Apache syntax is line-oriented:
//
//   - simple directives:    Directive arg1 arg2 [\ continuation]
//   - block sections:       <VirtualHost *:80> ... </VirtualHost>
//   - line comments:        # comment to end of line
//   - quoted arguments:     "with spaces"
//
// The parser preserves leading whitespace, comments, and quoting so a
// write-back round-trip lands close to the original file. It does *not*
// resolve Include / IncludeOptional directives — Phase 6 operates on the file
// you point it at; see CHANGES.md for the scope.
package parser

import (
	"fmt"
	"strings"
)

// Node is a top-level (or in-section) element: Directive, Section, Comment,
// or Blank line (used to preserve formatting).
type Node interface {
	emit(sb *strings.Builder)
	isNode()
}

// Config is the top-level container.
type Config struct {
	Nodes []Node
}

func (c *Config) String() string {
	var sb strings.Builder
	for _, n := range c.Nodes {
		n.emit(&sb)
	}
	return sb.String()
}

// Directive is a single line: indent + name + args + trailing.
type Directive struct {
	Indent          string   // leading whitespace
	Name            string
	Args            []string // already-cleaned arg tokens (quoted strings keep quotes)
	TrailingComment string   // including leading space and '#'; empty if none
	Newline         string   // "\n" or "" at EOF
}

func (d *Directive) isNode() {}
func (d *Directive) emit(sb *strings.Builder) {
	sb.WriteString(d.Indent)
	sb.WriteString(d.Name)
	for _, a := range d.Args {
		sb.WriteString(" ")
		sb.WriteString(a)
	}
	if d.TrailingComment != "" {
		sb.WriteString(d.TrailingComment)
	}
	sb.WriteString(d.Newline)
}

// Section is `<Name attrs>...</Name>`. The closing tag is regenerated using
// Name verbatim; whitespace around it is preserved.
type Section struct {
	OpenIndent      string
	Name            string   // VirtualHost, Directory, Location, IfModule, ...
	Args            []string
	OpenTrailing    string   // trailing comment after '>'; empty if none
	OpenNewline     string   // "\n" after the open tag
	Body            []Node
	CloseIndent     string
	CloseTrailing   string
	CloseNewline    string
}

func (s *Section) isNode() {}
func (s *Section) emit(sb *strings.Builder) {
	sb.WriteString(s.OpenIndent)
	sb.WriteString("<")
	sb.WriteString(s.Name)
	for _, a := range s.Args {
		sb.WriteString(" ")
		sb.WriteString(a)
	}
	sb.WriteString(">")
	if s.OpenTrailing != "" {
		sb.WriteString(s.OpenTrailing)
	}
	sb.WriteString(s.OpenNewline)
	for _, n := range s.Body {
		n.emit(sb)
	}
	sb.WriteString(s.CloseIndent)
	sb.WriteString("</")
	sb.WriteString(s.Name)
	sb.WriteString(">")
	if s.CloseTrailing != "" {
		sb.WriteString(s.CloseTrailing)
	}
	sb.WriteString(s.CloseNewline)
}

// CommentLine is `# ...` or a blank line — Verbatim is the line including
// any leading whitespace, but excluding the terminating newline.
type CommentLine struct {
	Verbatim string
	Newline  string
}

func (c *CommentLine) isNode() {}
func (c *CommentLine) emit(sb *strings.Builder) {
	sb.WriteString(c.Verbatim)
	sb.WriteString(c.Newline)
}

// Parse turns httpd.conf source into the AST.
func Parse(src string) (*Config, error) {
	lines := logicalLines(src)
	p := &parserState{lines: lines}
	cfg := &Config{}
	if err := p.parseBody(&cfg.Nodes, ""); err != nil {
		return nil, err
	}
	return cfg, nil
}

type logicalLine struct {
	Raw     string // the line as in source (after joining continuations)
	Newline string // "\n" or "" at EOF
}

// logicalLines splits src into physical lines and merges those joined by a
// trailing backslash so the parser sees one logical directive per element.
func logicalLines(src string) []logicalLine {
	var out []logicalLine
	pending := ""
	for len(src) > 0 {
		var line string
		nl := ""
		if i := strings.IndexByte(src, '\n'); i >= 0 {
			line = src[:i]
			nl = "\n"
			src = src[i+1:]
		} else {
			line = src
			src = ""
		}
		if strings.HasSuffix(line, "\\") {
			pending += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		out = append(out, logicalLine{Raw: pending + line, Newline: nl})
		pending = ""
	}
	if pending != "" {
		out = append(out, logicalLine{Raw: pending})
	}
	return out
}

type parserState struct {
	lines []logicalLine
	pos   int
}

// parseBody reads lines until either the matching `</closeTag>` is seen or
// EOF (when closeTag == ""). Returns nil error on success.
func (p *parserState) parseBody(nodes *[]Node, closeTag string) error {
	for p.pos < len(p.lines) {
		ll := p.lines[p.pos]
		trimmed := strings.TrimSpace(ll.Raw)
		if trimmed == "" {
			*nodes = append(*nodes, &CommentLine{Verbatim: ll.Raw, Newline: ll.Newline})
			p.pos++
			continue
		}
		indent := leadingWhitespace(ll.Raw)
		content := strings.TrimLeft(ll.Raw, " \t")
		if strings.HasPrefix(content, "#") {
			*nodes = append(*nodes, &CommentLine{Verbatim: ll.Raw, Newline: ll.Newline})
			p.pos++
			continue
		}
		if strings.HasPrefix(content, "</") {
			// Close tag.
			tag, trailing, err := parseCloseTag(content)
			if err != nil {
				return fmt.Errorf("apache: %w (line %d)", err, p.pos+1)
			}
			if closeTag == "" {
				return fmt.Errorf("apache: unmatched </%s> at line %d", tag, p.pos+1)
			}
			if !strings.EqualFold(tag, closeTag) {
				return fmt.Errorf("apache: expected </%s>, got </%s> (line %d)", closeTag, tag, p.pos+1)
			}
			// Don't consume here — caller's parseSection takes the line.
			_ = trailing
			return nil
		}
		if strings.HasPrefix(content, "<") {
			sec, err := p.parseSection(indent, content, ll.Newline)
			if err != nil {
				return err
			}
			*nodes = append(*nodes, sec)
			continue
		}
		d, err := parseDirective(indent, content, ll.Newline)
		if err != nil {
			return fmt.Errorf("apache: %w (line %d)", err, p.pos+1)
		}
		*nodes = append(*nodes, d)
		p.pos++
	}
	if closeTag != "" {
		return fmt.Errorf("apache: missing </%s> before EOF", closeTag)
	}
	return nil
}

func (p *parserState) parseSection(indent, content, newline string) (*Section, error) {
	// content starts with '<'; find the matching '>' (not inside a quoted arg).
	if !strings.HasPrefix(content, "<") {
		return nil, fmt.Errorf("apache: not a section line: %q", content)
	}
	end, err := findUnquotedGT(content)
	if err != nil {
		return nil, err
	}
	inner := content[1:end] // strip < and >
	rest := content[end+1:]
	openTrailing := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		// Trailing inline comment after '>'.
		openTrailing = rest[i:]
		rest = strings.TrimSpace(rest[:i])
	} else {
		rest = strings.TrimSpace(rest)
	}
	if rest != "" {
		return nil, fmt.Errorf("apache: unexpected text after '>' in <%s>", inner)
	}
	fields, err := splitArgs(inner)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("apache: empty section opener <>")
	}
	sec := &Section{
		OpenIndent:   indent,
		Name:         fields[0],
		Args:         fields[1:],
		OpenTrailing: openTrailing,
		OpenNewline:  newline,
	}
	p.pos++ // consume the open tag
	if err := p.parseBody(&sec.Body, sec.Name); err != nil {
		return nil, err
	}
	if p.pos >= len(p.lines) {
		return nil, fmt.Errorf("apache: missing </%s> before EOF", sec.Name)
	}
	closeLine := p.lines[p.pos]
	closeContent := strings.TrimLeft(closeLine.Raw, " \t")
	tag, trailing, err := parseCloseTag(closeContent)
	if err != nil {
		return nil, err
	}
	_ = tag
	sec.CloseIndent = leadingWhitespace(closeLine.Raw)
	sec.CloseTrailing = trailing
	sec.CloseNewline = closeLine.Newline
	p.pos++ // consume the close tag
	return sec, nil
}

func parseCloseTag(s string) (tag, trailing string, err error) {
	// s starts with </name>...
	if !strings.HasPrefix(s, "</") {
		return "", "", fmt.Errorf("not a close tag: %q", s)
	}
	end := strings.Index(s, ">")
	if end < 0 {
		return "", "", fmt.Errorf("unterminated close tag: %q", s)
	}
	tag = strings.TrimSpace(s[2:end])
	if tag == "" {
		return "", "", fmt.Errorf("empty close tag")
	}
	rest := s[end+1:]
	if i := strings.Index(rest, "#"); i >= 0 {
		trailing = rest[i:]
	} else if strings.TrimSpace(rest) != "" {
		return "", "", fmt.Errorf("unexpected text after </%s>", tag)
	}
	return tag, trailing, nil
}

func parseDirective(indent, content, newline string) (*Directive, error) {
	// Split off any inline trailing comment first (but not inside quotes).
	body := content
	trailing := ""
	if i := findUnquotedHash(content); i >= 0 {
		body = strings.TrimRight(content[:i], " \t")
		trailing = content[i:]
		// Re-attach a leading space before the '#' if there was one, so emit
		// is byte-identical for the common "Foo bar  # baz" case.
		if i > 0 && (content[i-1] == ' ' || content[i-1] == '\t') {
			j := i - 1
			for j > 0 && (content[j-1] == ' ' || content[j-1] == '\t') {
				j--
			}
			trailing = content[j:]
			body = strings.TrimRight(content[:j], " \t")
		}
	}
	fields, err := splitArgs(body)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty directive line")
	}
	return &Directive{
		Indent:          indent,
		Name:            fields[0],
		Args:            fields[1:],
		TrailingComment: trailing,
		Newline:         newline,
	}, nil
}

// splitArgs tokenizes an Apache directive body into name + args, honoring
// "..." quoted strings (which keep their quotes in the output).
func splitArgs(s string) ([]string, error) {
	var out []string
	i := 0
	for i < len(s) {
		// skip whitespace
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			start := i
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
			out = append(out, s[start:i])
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out, nil
}

// findUnquotedGT returns the index of the first '>' in s that isn't inside a
// quoted segment. Errors if none found.
func findUnquotedGT(s string) (int, error) {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			if i+1 < len(s) {
				i++
			}
		case '"':
			inQuote = !inQuote
		case '>':
			if !inQuote {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unterminated section opener: %q", s)
}

func findUnquotedHash(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			if i+1 < len(s) {
				i++
			}
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

func leadingWhitespace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[:i]
}
