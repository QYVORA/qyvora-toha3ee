package script

import (
	"fmt"
	"time"
)

// Stmt is a single executable statement in a script.
type Stmt interface {
	// stmt is a sealed-trait marker: it returns a tag so the engine can
	// type-switch on the concrete statement without a dummy value.
	stmt() string
}

// Program is the root of a parsed script.
type Program struct {
	Stmts []Stmt // the top-level statements, in source order
}

// -- expressions -----------------------------------------------------------

// Expr is a value-producing expression.
type Expr interface{ expr() string }

// StringLit is a string that may carry $(...) interpolation segments.
type StringLit struct {
	Segs []Seg // literal text / $(_var) / $(prop) pieces, concatenated in order
}

// Seg is one piece of a StringLit: either literal text, a variable reference
// or a live session property read.
type Seg struct {
	Text string // literal text (used when Var and Prop are both empty)
	Var  string // non-empty: "$(_name)" reference
	Prop string // non-empty: "$(path)" session property
}

// NumLit is a numeric literal.
type NumLit struct{ Value string }

// IdentExpr references a script variable.
type IdentExpr struct{ Name string }

// ListExpr is a bracketed list literal: [a, b, c].
type ListExpr struct{ Items []Expr }

// PropExpr is a bare $(path) session property read.
type PropExpr struct{ Path string }

// expr() marker methods give the parser and engine a stable tag for each
// concrete expression type (used by Describe and the dry-run renderer).
func (StringLit) expr() string { return "string" }
func (NumLit) expr() string    { return "number" }
func (IdentExpr) expr() string { return "variable" }
func (ListExpr) expr() string  { return "list" }
func (PropExpr) expr() string  { return "property" }

// -- conditions ------------------------------------------------------------

// Cond is a boolean condition.
type Cond interface{ cond() string }

// BoolCond is a literal true/false.
type BoolCond struct{ Value bool }

// CmpCond compares two operands.
type CmpCond struct {
	Op string // ==, !=, <, >, <=, >=
	L  Expr
	R  Expr
}

// ContainsCond tests substring / list membership.
type ContainsCond struct{ L, R Expr }

// RunningCond tests whether a module is (not) running.
type RunningCond struct {
	Module Expr
	Negate bool // true for "is not running"
}

// NotCond negates a condition.
type NotCond struct{ C Cond }

// AndCond combines two conditions with logical AND.
type AndCond struct{ L, R Cond }

// OrCond combines two conditions with logical OR.
type OrCond struct{ L, R Cond }

// cond() marker methods tag each concrete condition for the dry-run renderer.
func (BoolCond) cond() string     { return "bool" }
func (CmpCond) cond() string      { return "comparison" }
func (ContainsCond) cond() string { return "contains" }
func (RunningCond) cond() string  { return "running" }
func (NotCond) cond() string      { return "not" }
func (AndCond) cond() string      { return "and" }
func (OrCond) cond() string       { return "or" }

// -- statements ------------------------------------------------------------

// AssignStmt sets or appends to a script variable.
type AssignStmt struct {
	Var   string
	Op    string // "=", "->" or ">>"
	Value Expr
}

// SetStmt writes a module configuration key ("set module.key -> value").
type SetStmt struct {
	Key   string
	Value Expr
}

// GetStmt reads a module configuration key into a variable.
type GetStmt struct {
	Key string
	Var string
}

// StartStmt starts a module, optionally with inline "key value" options.
type StartStmt struct {
	ID   string
	Opts []Expr // flattened "key value key value" option tokens
}

// StopStmt stops a running module.
type StopStmt struct{ ID string }

// WaitStmt blocks until a module finishes (wait for <module> [max <secs>]).
type WaitStmt struct {
	Module string
	Max    time.Duration
}

// SleepStmt pauses the script.
type SleepStmt struct{ Seconds Expr }

// EchoStmt prints a value.
type EchoStmt struct{ Value Expr }

// ShowStmt prints module metadata.
type ShowStmt struct{ ID string }

// ReportStmt writes a session report.
type ReportStmt struct{ Path Expr }

// ExecStmt runs a one-shot REPL command line verbatim.
type ExecStmt struct{ Raw string }

// IfStmt is a conditional block.
type IfStmt struct {
	Cond Cond
	Then []Stmt
	Else []Stmt // may be empty when there is no else clause
}

// ForEachStmt iterates a list.
type ForEachStmt struct {
	Var  string // loop variable name (must start with '_')
	List Expr
	Body []Stmt
}

// RepeatStmt repeats a block N times.
type RepeatStmt struct {
	N    Expr // number of iterations (a numeric expression)
	Body []Stmt
}

// WhileStmt loops while a condition holds.
type WhileStmt struct {
	Cond Cond
	Body []Stmt
}

// BreakStmt exits the innermost loop.
type BreakStmt struct{}

// ContinueStmt jumps to the next loop iteration.
type ContinueStmt struct{}

// HaltStmt stops the whole script.
type HaltStmt struct{}

// stmt() marker methods tag each concrete statement for the engine switch and
// the dry-run renderer.
func (AssignStmt) stmt() string   { return "assign" }
func (SetStmt) stmt() string      { return "set" }
func (GetStmt) stmt() string      { return "get" }
func (StartStmt) stmt() string    { return "start" }
func (StopStmt) stmt() string     { return "stop" }
func (WaitStmt) stmt() string     { return "wait" }
func (SleepStmt) stmt() string    { return "sleep" }
func (EchoStmt) stmt() string     { return "echo" }
func (ShowStmt) stmt() string     { return "show" }
func (ExecStmt) stmt() string     { return "exec" }
func (ReportStmt) stmt() string   { return "report" }
func (IfStmt) stmt() string       { return "if" }
func (ForEachStmt) stmt() string  { return "for-each" }
func (RepeatStmt) stmt() string   { return "repeat" }
func (WhileStmt) stmt() string    { return "while" }
func (BreakStmt) stmt() string    { return "break" }
func (ContinueStmt) stmt() string { return "continue" }
func (HaltStmt) stmt() string     { return "halt" }

// parseError reports a syntax error at a line.
func parseError(tok token, format string, args ...any) error {
	// Format is expanded eagerly so the caller's variadic args are consumed
	// exactly once even when wrapped by fmt.Errorf later.
	return fmt.Errorf("script: line %d: %s", tok.line, fmt.Sprintf(format, args...))
}
