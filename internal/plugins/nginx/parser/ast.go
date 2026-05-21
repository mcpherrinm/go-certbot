package parser

import (
	"strings"
)

// Node is anything that appears in a config: a directive, a block, a comment,
// or trailing whitespace. The leading whitespace before each Node is preserved
// as part of the Node itself so re-emit retains the file's shape.
type Node interface {
	emit(sb *strings.Builder)
	isNode()
}

// Config is the top-level container.
type Config struct {
	Nodes []Node
	// TrailingWhitespace is whatever came after the last node (typically a newline).
	TrailingWhitespace string
}

func (c *Config) String() string {
	var sb strings.Builder
	for _, n := range c.Nodes {
		n.emit(&sb)
	}
	sb.WriteString(c.TrailingWhitespace)
	return sb.String()
}

// Directive is a "name args;" entry.
type Directive struct {
	Whitespace string   // whitespace before Name
	Name       string
	Args       []string // raw token values (quoted strings keep their quotes)
	// Whether the directive was terminated with a semicolon. Always true for
	// real nginx directives, but we keep the bit explicit so Emit can be lossless.
	Semicolon bool
	// Inline comment that appeared on the same line after the ';'. Empty if
	// none. Includes leading whitespace and the '#'.
	TrailingComment string
}

func (d *Directive) isNode() {}
func (d *Directive) emit(sb *strings.Builder) {
	sb.WriteString(d.Whitespace)
	sb.WriteString(d.Name)
	for _, a := range d.Args {
		sb.WriteString(" ")
		sb.WriteString(a)
	}
	if d.Semicolon {
		sb.WriteString(";")
	}
	if d.TrailingComment != "" {
		sb.WriteString(d.TrailingComment)
	}
}

// Block is a directive that opens a {...} body.
type Block struct {
	Whitespace string
	Name       string
	Args       []string
	Body       []Node
	// Whitespace immediately before the closing brace.
	BeforeClose string
}

func (b *Block) isNode() {}
func (b *Block) emit(sb *strings.Builder) {
	sb.WriteString(b.Whitespace)
	sb.WriteString(b.Name)
	for _, a := range b.Args {
		sb.WriteString(" ")
		sb.WriteString(a)
	}
	sb.WriteString(" {")
	for _, n := range b.Body {
		n.emit(sb)
	}
	sb.WriteString(b.BeforeClose)
	sb.WriteString("}")
}

// Comment is a standalone (non-trailing) comment line.
type Comment struct {
	Whitespace string
	Value      string // includes leading '#'
}

func (c *Comment) isNode() {}
func (c *Comment) emit(sb *strings.Builder) {
	sb.WriteString(c.Whitespace)
	sb.WriteString(c.Value)
}
