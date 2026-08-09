package script

import (
	"strconv"
	"strings"
	"time"
)

// parser is a recursive-descent parser for the toha3ee scripting language.
// Newlines terminate statements; blocks are opened with if/for/repeat/while
// and closed with `end` (or `else` for the middle of an if).
type parser struct {
	toks []token
	pos  int
}

// Parse parses src into a Program.
func Parse(src string) (*Program, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	return p.parseProgram()
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) at(kind tokKind) bool { return p.peek().kind == kind }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) expect(kind tokKind, what string) (token, error) {
	t := p.peek()
	if t.kind != kind {
		return t, parseError(t, "expected %s, found %s", what, t)
	}
	return p.next(), nil
}

// skipNewlines consumes newline tokens (and stops at non-newline tokens).
func (p *parser) skipNewlines() {
	for p.at(tkNewline) {
		p.next()
	}
}

// parseProgram parses a whole script.
func (p *parser) parseProgram() (*Program, error) {
	prog := &Program{}
	p.skipNewlines()
	for !p.at(tkEOF) {
		stmt, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		prog.Stmts = append(prog.Stmts, stmt)
		p.skipNewlines()
	}
	return prog, nil
}

// parseStmt parses a single statement (already positioned at its first token).
func (p *parser) parseStmt() (Stmt, error) {
	t := p.peek()
	if t.kind == tkNewline || t.kind == tkEOF {
		return nil, parseError(t, "expected a statement, found %s", t)
	}

	if t.kind == tkIdent {
		switch t.text {
		case "set":
			return p.parseSet()
		case "get":
			return p.parseGet()
		case "on", "start", "run":
			return p.parseStart()
		case "off":
			return p.parseStop()
		case "stop":
			// `stop` alone halts the script; `stop <module>` stops a module.
			if p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind != tkNewline && p.toks[p.pos+1].kind != tkEOF {
				return p.parseStop()
			}
			p.next()
			return HaltStmt{}, nil
		case "wait":
			return p.parseWait()
		case "sleep":
			return p.parseSleep()
		case "echo", "say", "print":
			return p.parseEcho()
		case "show":
			return p.parseShow()
		case "exec", "run.cmd", "command":
			return p.parseExec()
		case "report":
			return p.parseReport()
		case "if":
			return p.parseIf()
		case "for":
			return p.parseForEach()
		case "repeat":
			return p.parseRepeat()
		case "while":
			return p.parseWhile()
		case "break":
			p.next()
			return BreakStmt{}, nil
		case "continue":
			p.next()
			return ContinueStmt{}, nil
		case "end", "else":
			return nil, parseError(t, "unexpected %q", t.text)
		}

		// Variable assignment: `_var -> val` / `_var = val` / `_var >> val`.
		if strings.HasPrefix(t.text, "_") {
			op := p.toks[p.pos+1].kind
			if op == tkArrow || op == tkAssign || op == tkAppend {
				p.next() // var
				opTok := p.next()
				val, err := p.parseExprValue()
				if err != nil {
					return nil, err
				}
				op := "="
				switch opTok.kind {
				case tkArrow:
					op = "->"
				case tkAppend:
					op = ">>"
				}
				return AssignStmt{Var: t.text, Op: op, Value: val}, nil
			}
		}
	}

	return nil, parseError(t, "expected a statement, found %s", t)
}

func (p *parser) parseSet() (Stmt, error) {
	p.next() // set
	key, err := p.expect(tkIdent, "a module key like net.scan.targets")
	if err != nil {
		return nil, err
	}
	if !p.at(tkArrow) && !p.at(tkAssign) {
		return nil, parseError(p.peek(), "expected '->' or '=', found %s", p.peek())
	}
	p.next()
	val, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	return SetStmt{Key: key.text, Value: val}, nil
}

func (p *parser) parseGet() (Stmt, error) {
	p.next() // get
	key, err := p.expect(tkIdent, "a module key like net.scan.targets")
	if err != nil {
		return nil, err
	}
	if !p.at(tkArrow) && !p.at(tkAssign) {
		return nil, parseError(p.peek(), "expected '->', found %s", p.peek())
	}
	p.next()
	v, err := p.expect(tkIdent, "a target variable like _targets")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(v.text, "_") {
		return nil, parseError(v, "target variable must start with '_'")
	}
	return GetStmt{Key: key.text, Var: v.text}, nil
}

func (p *parser) parseStart() (Stmt, error) {
	p.next() // on / start / run
	id, err := p.expect(tkIdent, "a module id like arp.spoof")
	if err != nil {
		return nil, err
	}
	// Inline "key value" options until end of line. Values may join
	// comma-separated pieces without quotes, so "ports 80,443" works.
	var opts []Expr
	for !p.at(tkNewline) && !p.at(tkEOF) {
		if p.at(tkComma) {
			p.next()
			continue
		}
		var e Expr
		var err error
		if len(opts)%2 == 1 { // expecting a value
			e, err = p.parseOptValue()
		} else {
			e, err = p.parseExprValue()
		}
		if err != nil {
			return nil, err
		}
		opts = append(opts, e)
	}
	return StartStmt{ID: id.text, Opts: opts}, nil
}

// parseOptValue parses a module option value, joining any comma-separated
// pieces into a single string ("80,443", "10.0.0.1,10.0.0.2").
func (p *parser) parseOptValue() (Expr, error) {
	first, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	if !p.at(tkComma) {
		return first, nil
	}
	segs := optValueSegs(first)
	for p.at(tkComma) {
		p.next()
		e, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		segs = append(segs, Seg{Text: ","})
		segs = append(segs, optValueSegs(e)...)
	}
	return StringLit{Segs: segs}, nil
}

// optValueSegs flattens an option-value piece into interpolation segments so
// that joining comma-separated pieces keeps $(...) references live instead of
// turning them into literal text.
func optValueSegs(e Expr) []Seg {
	switch v := e.(type) {
	case StringLit:
		return v.Segs
	case PropExpr:
		return []Seg{{Prop: v.Path}}
	case IdentExpr:
		return []Seg{{Var: v.Name}}
	default:
		return []Seg{{Text: exprText(e)}}
	}
}

func (p *parser) parseStop() (Stmt, error) {
	p.next() // off / stop
	id, err := p.expect(tkIdent, "a module id like arp.spoof")
	if err != nil {
		return nil, err
	}
	return StopStmt{ID: id.text}, nil
}

func (p *parser) parseWait() (Stmt, error) {
	p.next() // wait
	if p.at(tkIdent) && p.peek().text == "for" {
		p.next() // for
		id, err := p.expect(tkIdent, "a module id like net.scan")
		if err != nil {
			return nil, err
		}
		max := 10 * time.Minute
		if p.at(tkIdent) && p.peek().text == "max" {
			p.next()
			valTok := p.peek()
			secs, err := p.parseExprValue()
			if err != nil {
				return nil, err
			}
			if n, ok := numOf(secs); ok {
				max = time.Duration(n * float64(time.Second))
			} else {
				return nil, parseError(valTok, "wait for %s max needs a number of seconds, found %s", id.text, valTok)
			}
		}
		return WaitStmt{Module: id.text, Max: max}, nil
	}
	secs, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	return SleepStmt{Seconds: secs}, nil
}

func (p *parser) parseSleep() (Stmt, error) {
	p.next() // sleep
	if p.at(tkArrow) {
		p.next()
	}
	secs, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	return SleepStmt{Seconds: secs}, nil
}

// parseExec captures the rest of the line verbatim as a one-shot REPL command,
// so scripts can call commands like "net.profile" or "creds.show".
func (p *parser) parseExec() (Stmt, error) {
	p.next() // exec / run.cmd / command
	if p.at(tkArrow) || p.at(tkAppend) {
		p.next()
	}
	var parts []string
	for !p.at(tkNewline) && !p.at(tkEOF) {
		t := p.next()
		if t.kind == tkString {
			parts = append(parts, t.text)
			continue
		}
		parts = append(parts, t.text)
	}
	return ExecStmt{Raw: strings.Join(parts, " ")}, nil
}

func (p *parser) parseEcho() (Stmt, error) {
	p.next() // echo / say / print
	if p.at(tkArrow) {
		p.next()
	}
	val, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	return EchoStmt{Value: val}, nil
}

func (p *parser) parseShow() (Stmt, error) {
	p.next() // show
	id, err := p.expect(tkIdent, "a module id like arp.spoof")
	if err != nil {
		return nil, err
	}
	return ShowStmt{ID: id.text}, nil
}

func (p *parser) parseReport() (Stmt, error) {
	p.next() // report
	if p.at(tkArrow) {
		p.next()
	}
	val, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	return ReportStmt{Path: val}, nil
}

func (p *parser) parseIf() (Stmt, error) {
	p.next() // if
	cond, err := p.parseCond()
	if err != nil {
		return nil, err
	}
	if err := p.endOfLine(); err != nil {
		return nil, err
	}
	then, term, err := p.parseBlock(true)
	if err != nil {
		return nil, err
	}
	stmt := IfStmt{Cond: cond, Then: then}
	if term == "else" {
		p.next() // else
		if err := p.endOfLine(); err != nil {
			return nil, err
		}
		els, term2, err := p.parseBlock(false)
		if err != nil {
			return nil, err
		}
		stmt.Else = els
		if term2 != "end" {
			return nil, parseError(p.peek(), "expected 'end', found %s", p.peek())
		}
		p.next()
	} else {
		p.next() // end
	}
	return stmt, nil
}

func (p *parser) parseForEach() (Stmt, error) {
	p.next() // for
	if !(p.at(tkIdent) && p.peek().text == "each") {
		return nil, parseError(p.peek(), "expected 'each', found %s", p.peek())
	}
	p.next()
	v, err := p.expect(tkIdent, "a loop variable like _item")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(v.text, "_") {
		return nil, parseError(v, "loop variable must start with '_'")
	}
	if !(p.at(tkIdent) && p.peek().text == "in") {
		return nil, parseError(p.peek(), "expected 'in', found %s", p.peek())
	}
	p.next()
	list, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	if err := p.endOfLine(); err != nil {
		return nil, err
	}
	body, term, err := p.parseBlock(false)
	if err != nil {
		return nil, err
	}
	if term != "end" {
		return nil, parseError(p.peek(), "expected 'end', found %s", p.peek())
	}
	p.next()
	return ForEachStmt{Var: v.text, List: list, Body: body}, nil
}

func (p *parser) parseRepeat() (Stmt, error) {
	p.next() // repeat
	n, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}
	if !(p.at(tkIdent) && p.peek().text == "times") {
		return nil, parseError(p.peek(), "expected 'times', found %s", p.peek())
	}
	p.next()
	if err := p.endOfLine(); err != nil {
		return nil, err
	}
	body, term, err := p.parseBlock(false)
	if err != nil {
		return nil, err
	}
	if term != "end" {
		return nil, parseError(p.peek(), "expected 'end', found %s", p.peek())
	}
	p.next()
	return RepeatStmt{N: n, Body: body}, nil
}

func (p *parser) parseWhile() (Stmt, error) {
	p.next() // while
	cond, err := p.parseCond()
	if err != nil {
		return nil, err
	}
	if err := p.endOfLine(); err != nil {
		return nil, err
	}
	body, term, err := p.parseBlock(false)
	if err != nil {
		return nil, err
	}
	if term != "end" {
		return nil, parseError(p.peek(), "expected 'end', found %s", p.peek())
	}
	p.next()
	return WhileStmt{Cond: cond, Body: body}, nil
}

// parseBlock parses statements until "end" (or "else", when stopOnElse is
// true). It returns the statements plus the terminator token's text.
func (p *parser) parseBlock(stopOnElse bool) ([]Stmt, string, error) {
	var stmts []Stmt
	for {
		p.skipNewlines()
		t := p.peek()
		switch {
		case t.kind == tkEOF:
			return nil, "", parseError(t, "expected 'end' before end of script")
		case t.kind == tkIdent && t.text == "end":
			return stmts, "end", nil
		case t.kind == tkIdent && t.text == "else" && stopOnElse:
			return stmts, "else", nil
		case t.kind == tkNewline:
			continue
		}
		stmt, err := p.parseStmt()
		if err != nil {
			return nil, "", err
		}
		stmts = append(stmts, stmt)
	}
}

// endOfLine verifies the current statement line is finished (newline or EOF).
func (p *parser) endOfLine() error {
	t := p.peek()
	if t.kind != tkNewline && t.kind != tkEOF {
		return parseError(t, "unexpected %s after statement", t)
	}
	return nil
}

// -- conditions ------------------------------------------------------------

func (p *parser) parseCond() (Cond, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.at(tkOr) {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = OrCond{L: left, R: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Cond, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.at(tkAnd) {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = AndCond{L: left, R: right}
	}
	return left, nil
}

func (p *parser) parseNot() (Cond, error) {
	t := p.peek()
	if (t.kind == tkNot) || (t.kind == tkIdent && t.text == "not") {
		p.next()
		c, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return NotCond{C: c}, nil
	}
	return p.parsePrimaryCond()
}

func (p *parser) parsePrimaryCond() (Cond, error) {
	// Bare true/false.
	if p.at(tkIdent) {
		if p.peek().text == "true" || p.peek().text == "false" {
			next := p.toks[p.pos+1]
			if !isCondOp(next) {
				p.next()
				return BoolCond{Value: p.toks[p.pos-1].text == "true"}, nil
			}
		}
	}

	left, err := p.parseExprValue()
	if err != nil {
		return nil, err
	}

	t := p.peek()
	switch {
	case t.kind == tkEq:
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return CmpCond{Op: "==", L: left, R: right}, nil
	case t.kind == tkNe:
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return CmpCond{Op: "!=", L: left, R: right}, nil
	case t.kind == tkLt:
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return CmpCond{Op: "<", L: left, R: right}, nil
	case t.kind == tkGt:
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return CmpCond{Op: ">", L: left, R: right}, nil
	case t.kind == tkLe:
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return CmpCond{Op: "<=", L: left, R: right}, nil
	case t.kind == tkGe:
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return CmpCond{Op: ">=", L: left, R: right}, nil
	case t.kind == tkIdent && t.text == "contains":
		p.next()
		right, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		return ContainsCond{L: left, R: right}, nil
	case t.kind == tkIdent && t.text == "is":
		p.next()
		neg := false
		if p.at(tkIdent) && p.peek().text == "not" {
			neg = true
			p.next()
		}
		if !(p.at(tkIdent) && p.peek().text == "running") {
			return nil, parseError(p.peek(), "expected 'running', found %s", p.peek())
		}
		p.next()
		return RunningCond{Module: left, Negate: neg}, nil
	default:
		if sl, ok := left.(StringLit); ok && len(sl.Segs) == 1 {
			seg := sl.Segs[0]
			if seg.Text == "true" {
				return BoolCond{Value: true}, nil
			}
			if seg.Text == "false" {
				return BoolCond{Value: false}, nil
			}
		}
		return nil, parseError(t, "expected a comparison, found %s", t)
	}
}

// isCondOp reports whether tok can continue a condition expression.
func isCondOp(t token) bool {
	switch t.kind {
	case tkEq, tkNe, tkLt, tkGt, tkLe, tkGe, tkAnd, tkOr:
		return true
	}
	return t.kind == tkIdent && (t.text == "contains" || t.text == "is")
}

// -- expressions -----------------------------------------------------------

// parseExprValue parses a value expression: string, number, variable, $(...)
// property, or list.
func (p *parser) parseExprValue() (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tkString:
		p.next()
		if t.raw {
			// Single-quoted strings are literal: no escapes, no $(...) interpolation.
			return StringLit{Segs: []Seg{{Text: t.text}}}, nil
		}
		return parseSegments(t.text), nil
	case tkIdent:
		p.next()
		if strings.HasPrefix(t.text, "_") {
			return IdentExpr{Name: t.text}, nil
		}
		return StringLit{Segs: []Seg{{Text: t.text}}}, nil
	case tkDollar:
		p.next()
		path, err := p.expect(tkIdent, "a property path like hosts.count")
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkRParen, "')'"); err != nil {
			return nil, err
		}
		return PropExpr{Path: path.text}, nil
	case tkLBrack:
		return p.parseList()
	case tkLParen:
		p.next()
		inner, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkRParen, "')'"); err != nil {
			return nil, err
		}
		return inner, nil
	default:
		return nil, parseError(t, "expected a value, found %s", t)
	}
}

func (p *parser) parseList() (Expr, error) {
	p.next() // [
	list := ListExpr{}
	p.skipInline()
	for !p.at(tkRBrack) {
		item, err := p.parseExprValue()
		if err != nil {
			return nil, err
		}
		list.Items = append(list.Items, item)
		p.skipInline()
		if p.at(tkComma) {
			p.next()
			p.skipInline()
		}
	}
	p.next() // ]
	return list, nil
}

// skipInline consumes the few whitespace-only tokens that may appear inside a
// list literal between items.
func (p *parser) skipInline() {
	for {
		t := p.peek()
		if t.kind == tkNewline {
			p.next()
			continue
		}
		return
	}
}

// parseSegments splits a raw string into literal / $(_var) / $(prop) segments.
func parseSegments(s string) StringLit {
	lit := StringLit{}
	for {
		idx := strings.Index(s, "$(")
		if idx < 0 {
			if s != "" {
				lit.Segs = append(lit.Segs, Seg{Text: s})
			}
			break
		}
		if idx > 0 {
			lit.Segs = append(lit.Segs, Seg{Text: s[:idx]})
		}
		rest := s[idx+2:]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			lit.Segs = append(lit.Segs, Seg{Text: s[idx:]})
			break
		}
		path := rest[:end]
		if strings.HasPrefix(path, "_") {
			lit.Segs = append(lit.Segs, Seg{Var: path})
		} else {
			lit.Segs = append(lit.Segs, Seg{Prop: path})
		}
		s = rest[end+1:]
	}
	if len(lit.Segs) == 0 {
		lit.Segs = []Seg{{Text: ""}}
	}
	return lit
}

// unquoteText renders an expression as plain text, removing the surrounding
// quotes that exprText adds to string literals.
func unquoteText(e Expr) string {
	s := exprText(e)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// numOf extracts a number from a literal expression, when the expression is
// a plain string or number literal.
func numOf(e Expr) (float64, bool) {
	var s string
	switch v := e.(type) {
	case StringLit:
		if len(v.Segs) != 1 || v.Segs[0].Var != "" || v.Segs[0].Prop != "" {
			return 0, false
		}
		s = v.Segs[0].Text
	case NumLit:
		s = v.Value
	case IdentExpr:
		return 0, false
	default:
		return 0, false
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
