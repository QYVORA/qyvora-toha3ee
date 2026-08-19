// Package script implements the toha3ee scripting language, an English-like,
// line-oriented DSL that lives in ".toha3ee" files. A script drives the
// whole recon → attack → report pipeline without any manual REPL work:
//
//	# a full pipeline, end to end
//	set net.scan.targets -> "192.168.8.0/24"
//	on net.scan
//	wait for net.scan
//	_hosts -> [$(net.hosts)]
//	echo -> "discovered $(_hosts.size) host(s)"
//
//	sleep -> 2
//	on service.synscan
//	wait for service.synscan
//	on service.fingerprint
//	wait for service.fingerprint
//
//	if $(hosts.count) > 0
//	    on arp.spoof targets $(_hosts)
//	    sleep -> 30
//	    off arp.spoof
//	end
//	report -> "assessment.md"
//
// The syntax is deliberately small: `->` / `=` assign, `>>` appends to a
// list, `_` prefixes variable names, `$(...)` interpolates live session
// state, and the control flow reads like English (`for each`, `repeat
// N times`, `if`/`else`/`end`, `while`).
package script

import (
	"fmt"
	"strings"
)

// tokKind identifies a single lexical token.
type tokKind int

// Token kinds. The iota block is an ordered enum; new kinds must be appended,
// never inserted, to keep any persisted or test expectations stable.
const (
	tkEOF tokKind = iota
	tkNewline
	tkIdent // names, module ids, keywords, raw values
	tkString
	tkArrow  // ->
	tkAssign // =
	tkAppend // >>
	tkEq     // ==
	tkNe     // !=
	tkLt     // <
	tkGt     // >
	tkLe     // <=
	tkGe     // >=
	tkAnd    // &&
	tkOr     // ||
	tkNot    // !
	tkLBrack // [
	tkRBrack // ]
	tkComma  // ,
	tkLParen // (
	tkRParen // )
	tkDollar // $(
)

// token is a single lexical token with its source position.
type token struct {
	kind tokKind
	text string
	line int
	raw  bool // true: single-quoted literal, no interpolation
}

func (t token) String() string {
	switch t.kind {
	case tkEOF:
		return "end of script"
	case tkNewline:
		return "newline"
	default:
		return fmt.Sprintf("%q", t.text)
	}
}

// lexer turns source text into a stream of tokens. Newlines are significant:
// every statement lives on one line and blocks are closed with `end`.
type lexer struct {
	src  string
	pos  int // current byte offset into src
	line int // 1-based line of the current position
	toks []token
}

// lex tokenizes src. It returns the full token slice (including a final EOF).
func lex(src string) ([]token, error) {
	l := &lexer{src: src, line: 1}
	for {
		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		l.toks = append(l.toks, tok)
		if tok.kind == tkEOF {
			break
		}
	}
	return l.toks, nil
}

// next produces the next token.
func (l *lexer) next() (token, error) {
	// The loop skips whitespace and comments before returning the next real
	// token; the explicit returns below exit as soon as one is found.
	for l.pos < len(l.src) {
		c := l.src[l.pos]

		switch {
		case c == '\n':
			// Newlines are real tokens: they terminate statements, so the
			// line number is captured before it increments.
			l.pos++
			line := l.line
			l.line++
			return token{kind: tkNewline, line: line}, nil

		case c == ' ' || c == '\t' || c == '\r':
			// Horizontal whitespace is insignificant between tokens.
			l.pos++
			continue

		case c == '#': // comment to end of line
			l.skipComment()
			continue

		case c == '/':
			// '//' is a comment; a lone '/' falls through to lexRaw (e.g. a
			// filesystem path or CIDR-adjacent text).
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
				l.skipComment()
				continue
			}

		case c == '-':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '>' {
				tok := token{kind: tkArrow, text: "->", line: l.line}
				l.pos += 2
				return tok, nil
			}
			// A bare '-' (not '->') is part of a raw value: negative numbers
			// like "-1" and command-line flags like "exec nmap -sS".
			return l.lexRaw()

		case c == '>':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '>' {
				tok := token{kind: tkAppend, text: ">>", line: l.line}
				l.pos += 2
				return tok, nil
			}
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
				tok := token{kind: tkGe, text: ">=", line: l.line}
				l.pos += 2
				return tok, nil
			}
			l.pos++
			return token{kind: tkGt, text: ">", line: l.line}, nil

		case c == '<':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
				tok := token{kind: tkLe, text: "<=", line: l.line}
				l.pos += 2
				return tok, nil
			}
			l.pos++
			return token{kind: tkLt, text: "<", line: l.line}, nil

		case c == '=':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
				tok := token{kind: tkEq, text: "==", line: l.line}
				l.pos += 2
				return tok, nil
			}
			l.pos++
			return token{kind: tkAssign, text: "=", line: l.line}, nil

		case c == '!':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
				tok := token{kind: tkNe, text: "!=", line: l.line}
				l.pos += 2
				return tok, nil
			}
			l.pos++
			return token{kind: tkNot, text: "!", line: l.line}, nil

		case c == '&':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '&' {
				tok := token{kind: tkAnd, text: "&&", line: l.line}
				l.pos += 2
				return tok, nil
			}
			// A lone '&' is not valid in scripts; it falls through to the
			// unexpected-character error below.

		case c == '|':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '|' {
				tok := token{kind: tkOr, text: "||", line: l.line}
				l.pos += 2
				return tok, nil
			}

		case c == '[':
			l.pos++
			return token{kind: tkLBrack, line: l.line}, nil

		case c == ']':
			l.pos++
			return token{kind: tkRBrack, line: l.line}, nil

		case c == ',':
			l.pos++
			return token{kind: tkComma, line: l.line}, nil

		case c == '(':
			l.pos++
			return token{kind: tkLParen, line: l.line}, nil

		case c == ')':
			l.pos++
			return token{kind: tkRParen, line: l.line}, nil

		case c == '$':
			// '$(' starts an interpolation; a bare '$' is a lex error.
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '(' {
				tok := token{kind: tkDollar, text: "$(", line: l.line}
				l.pos += 2
				return tok, nil
			}

		case c == '"':
			return l.lexQuoted()

		case c == '\'':
			return l.lexSingleQuoted()

		case isIdentStart(c):
			return l.lexIdent()

		default:
			// Anything else (e.g. '*', '~') must begin a raw value or be an
			// error; lexRaw decides which.
			return l.lexRaw()
		}

		return token{}, fmt.Errorf("line %d: unexpected character %q", l.line, string(c))
	}
	return token{kind: tkEOF, line: l.line}, nil
}

func (l *lexer) skipComment() {
	// Consume up to but not including the newline, which the main loop will
	// emit as its own token.
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.pos++
	}
}

// lexQuoted reads a double-quoted string with backslash escapes and $(...)
// interpolation. The raw text (without quotes) is preserved so the parser can
// split it into literal and interpolation segments.
func (l *lexer) lexQuoted() (token, error) {
	line := l.line
	l.pos++ // opening quote
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case '"':
			l.pos++
			return token{kind: tkString, text: b.String(), line: line}, nil
		case '\n':
			// Strings are single-line by design; a newline means the user
			// forgot the closing quote.
			return token{}, fmt.Errorf("line %d: unterminated string", line)
		case '\\':
			if l.pos+1 >= len(l.src) {
				return token{}, fmt.Errorf("line %d: trailing backslash in string", line)
			}
			esc := l.src[l.pos+1]
			switch esc {
			// Recognized escapes map to their control/quote equivalents; any
			// unknown escape (e.g. "\d") is kept verbatim so Windows paths and
			// regexes survive unchanged.
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case '$':
				b.WriteByte('$')
			default:
				b.WriteByte('\\')
				b.WriteByte(esc)
			}
			l.pos += 2
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return token{}, fmt.Errorf("line %d: unterminated string", line)
}

// lexSingleQuoted reads a single-quoted literal string (no escapes, no
// interpolation). It is the escape hatch when a value contains "$(...)" or
// backslashes that must stay literal.
func (l *lexer) lexSingleQuoted() (token, error) {
	line := l.line
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case '\'':
			l.pos++
			return token{kind: tkString, text: b.String(), line: line, raw: true}, nil
		case '\n':
			return token{}, fmt.Errorf("line %d: unterminated string", line)
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return token{}, fmt.Errorf("line %d: unterminated string", line)
}

// lexIdent reads an identifier: starts with a letter or underscore, then
// letters, digits, underscores and dots (so module keys like "arp.spoof" and
// variables like "_hosts" both lex as one token).
func (l *lexer) lexIdent() (token, error) {
	line := l.line
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	return token{kind: tkIdent, text: l.src[start:l.pos], line: line}, nil
}

// lexRaw reads a bare, unquoted value such as a number, an IP, a duration or
// a CIDR ("30", "5ms", "10.0.0.5", "192.168.1.0/24"). Values are carried as
// strings and parsed on demand. An unexpected character that cannot start a
// raw value is a lex error rather than being silently dropped.
func (l *lexer) lexRaw() (token, error) {
	line := l.line
	start := l.pos
	for l.pos < len(l.src) && isRawPart(l.src[l.pos]) {
		l.pos++
	}
	if l.pos == start {
		// No consumable characters: the character that led us here cannot
		// begin any valid token, so report it explicitly.
		return token{}, fmt.Errorf("line %d: unexpected character %q", line, string(l.src[l.pos]))
	}
	// Raw values lex as tkString so the parser treats them like literals.
	return token{kind: tkString, text: l.src[start:l.pos], line: line}, nil
}

// isIdentStart reports whether c can begin an identifier: underscore or letter.
func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isIdentPart reports whether c may continue an identifier, including the '.'
// that separates dotted module keys ("arp.spoof").
func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.'
}

// isRawPart matches characters that make up unquoted literal values. Leading
// digits (numbers, IPs, durations, CIDRs) all funnel through here.
func isRawPart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '.' || c == '/' || c == ':' ||
		c == '-' || c == '_' || c == '+'
}
