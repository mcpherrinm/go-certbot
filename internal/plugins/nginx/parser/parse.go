package parser

import (
	"fmt"
)

// Parse reads `src` as nginx configuration and returns the AST.
func Parse(src string) (*Config, error) {
	p := &parserState{lex: newLexer(src)}
	cfg := &Config{}
	if err := p.parseBody(&cfg.Nodes, true); err != nil {
		return nil, err
	}
	// Anything left after the final node is trailing whitespace from EOF token.
	cfg.TrailingWhitespace = p.lastWhitespace
	return cfg, nil
}

type parserState struct {
	lex            *lexer
	pending        *token // single-token lookahead
	lastWhitespace string // whitespace before final EOF token
}

func (p *parserState) peek() (token, error) {
	if p.pending != nil {
		return *p.pending, nil
	}
	t, err := p.lex.next()
	if err != nil {
		return token{}, err
	}
	p.pending = &t
	return t, nil
}

func (p *parserState) take() (token, error) {
	if p.pending != nil {
		t := *p.pending
		p.pending = nil
		return t, nil
	}
	return p.lex.next()
}

// parseBody parses directives, blocks, and comments until either EOF (top
// level) or a closing brace.
func (p *parserState) parseBody(nodes *[]Node, topLevel bool) error {
	for {
		t, err := p.peek()
		if err != nil {
			return err
		}
		switch t.Kind {
		case tokEOF:
			if !topLevel {
				return fmt.Errorf("nginx: unexpected EOF inside block")
			}
			_, _ = p.take()
			p.lastWhitespace = t.Whitespace
			return nil
		case tokCloseBrace:
			if topLevel {
				return fmt.Errorf("nginx: unexpected '}' at top level")
			}
			// Don't consume — caller's parseBlock takes it.
			return nil
		case tokComment:
			_, _ = p.take()
			*nodes = append(*nodes, &Comment{Whitespace: t.Whitespace, Value: t.Value})
			continue
		}
		// Otherwise: a directive or block. Read name + args.
		nameTok, err := p.take()
		if err != nil {
			return err
		}
		if nameTok.Kind != tokWord {
			return fmt.Errorf("nginx: expected directive name, got %s %q", nameTok.Kind, nameTok.Value)
		}
		ws := nameTok.Whitespace
		name := nameTok.Value
		var args []string
		for {
			next, err := p.peek()
			if err != nil {
				return err
			}
			if next.Kind == tokWord || next.Kind == tokQuotedString {
				_, _ = p.take()
				args = append(args, next.Value)
				continue
			}
			break
		}
		closer, err := p.take()
		if err != nil {
			return err
		}
		switch closer.Kind {
		case tokSemicolon:
			// Look for an inline trailing comment.
			trailing := ""
			if peek, err := p.peek(); err == nil && peek.Kind == tokComment && !containsNewline(peek.Whitespace) {
				_, _ = p.take()
				trailing = peek.Whitespace + peek.Value
			}
			*nodes = append(*nodes, &Directive{
				Whitespace:      ws,
				Name:            name,
				Args:            args,
				Semicolon:       true,
				TrailingComment: trailing,
			})
		case tokOpenBrace:
			block := &Block{Whitespace: ws, Name: name, Args: args}
			if err := p.parseBody(&block.Body, false); err != nil {
				return err
			}
			closeTok, err := p.take()
			if err != nil {
				return err
			}
			if closeTok.Kind != tokCloseBrace {
				return fmt.Errorf("nginx: expected '}', got %s", closeTok.Kind)
			}
			block.BeforeClose = closeTok.Whitespace
			*nodes = append(*nodes, block)
		default:
			return fmt.Errorf("nginx: expected ';' or '{' after '%s', got %s", name, closer.Kind)
		}
	}
}

func containsNewline(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return true
		}
	}
	return false
}
