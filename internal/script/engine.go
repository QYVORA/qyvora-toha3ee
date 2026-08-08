package script

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Runner is the bridge between a script and the live framework. The Session
// implements it, so scripts can be executed headless (toha3ee script ...) or
// from inside the REPL with exactly the same semantics.
type Runner interface {
	// Echo prints a value to the console.
	Echo(s string)
	// SetConfig writes a "module.key" configuration value.
	SetConfig(key, value string) error
	// GetConfig reads a "module.key" configuration value.
	GetConfig(key string) string
	// Start starts a module with inline options.
	Start(id string, opts map[string]string) error
	// Stop stops a running module.
	Stop(id string) error
	// IsRunning reports whether a module is live.
	IsRunning(id string) bool
	// Show prints module metadata.
	Show(id string) error
	// Report writes a session report.
	Report(path string) error
	// Cmd runs a one-shot REPL command line (e.g. "net.profile",
	// "vectors.show", "creds.show").
	Cmd(line string) error
	// Prop resolves a live session property for $(...) interpolation.
	Prop(name string) (string, bool)
}

// sentinel errors that drive control flow inside a script.
var (
	errBreak    = errors.New("script: break")
	errContinue = errors.New("script: continue")
	errStop     = errors.New("script: stop")
)

// maxLoop is the safety cap on while-loop iterations so a bad condition can
// never hang a script forever.
const maxLoop = 1000000

// Engine evaluates a parsed Program against a Runner.
type Engine struct {
	Runner Runner
	vars   map[string]value
}

// NewEngine returns an engine that drives r.
func NewEngine(r Runner) *Engine {
	return &Engine{Runner: r, vars: map[string]value{}}
}

// value is a script runtime value: either a scalar string or a list.
type value struct {
	s      string
	list   []string
	isList bool
}

func (v value) str() string {
	if v.isList {
		return strings.Join(v.list, ", ")
	}
	return v.s
}

// Run parses and executes src.
func (e *Engine) Run(src string) error {
	prog, err := Parse(src)
	if err != nil {
		return err
	}
	return e.RunProgram(prog)
}

// RunFile reads and executes a ".toha3ee" script file.
func (e *Engine) RunFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("script: read %s: %w", path, err)
	}
	return e.Run(string(data))
}

// RunProgram executes a parsed program.
func (e *Engine) RunProgram(prog *Program) error {
	for _, stmt := range prog.Stmts {
		if err := e.evalStmt(stmt); err != nil {
			if errors.Is(err, errStop) {
				return nil
			}
			if errors.Is(err, errBreak) || errors.Is(err, errContinue) {
				return fmt.Errorf("script: %w outside of a loop", err)
			}
			return err
		}
	}
	return nil
}

func (e *Engine) evalStmt(s Stmt) error {
	switch st := s.(type) {
	case AssignStmt:
		return e.assign(st)

	case SetStmt:
		val := e.evalExpr(st.Value)
		if err := e.Runner.SetConfig(st.Key, val.str()); err != nil {
			return fmt.Errorf("script: set %s: %w", st.Key, err)
		}
		return nil

	case GetStmt:
		e.vars[st.Var] = value{s: e.Runner.GetConfig(st.Key)}
		return nil

	case StartStmt:
		opts, err := evalOpts(e, st.Opts)
		if err != nil {
			return err
		}
		if err := e.Runner.Start(st.ID, opts); err != nil {
			return fmt.Errorf("script: %s: %w", st.ID, err)
		}
		return nil

	case StopStmt:
		if err := e.Runner.Stop(st.ID); err != nil {
			return fmt.Errorf("script: off %s: %w", st.ID, err)
		}
		return nil

	case WaitStmt:
		return e.wait(st)

	case SleepStmt:
		secs, ok := numFromValue(e.evalExpr(st.Seconds))
		if !ok {
			return fmt.Errorf("script: sleep needs a number of seconds")
		}
		time.Sleep(time.Duration(secs * float64(time.Second)))
		return nil

	case EchoStmt:
		e.Runner.Echo(e.evalExpr(st.Value).str())
		return nil

	case ShowStmt:
		if err := e.Runner.Show(st.ID); err != nil {
			return fmt.Errorf("script: show %s: %w", st.ID, err)
		}
		return nil

	case ExecStmt:
		if err := e.Runner.Cmd(st.Raw); err != nil {
			return fmt.Errorf("script: %s: %w", st.Raw, err)
		}
		return nil

	case ReportStmt:
		if err := e.Runner.Report(e.evalExpr(st.Path).str()); err != nil {
			return fmt.Errorf("script: report: %w", err)
		}
		return nil

	case IfStmt:
		if e.evalCond(st.Cond) {
			return e.evalBody(st.Then)
		}
		return e.evalBody(st.Else)

	case ForEachStmt:
		return e.forEach(st)

	case RepeatStmt:
		n, ok := numFromValue(e.evalExpr(st.N))
		if !ok {
			return fmt.Errorf("script: repeat needs a number")
		}
		for i := 0; i < int(n); i++ {
			if err := e.evalBody(st.Body); err != nil {
				return err
			}
		}
		return nil

	case WhileStmt:
		iterations := 0
		for e.evalCond(st.Cond) {
			iterations++
			if iterations > maxLoop {
				return fmt.Errorf("script: while loop exceeded %d iterations", maxLoop)
			}
			if err := e.evalBody(st.Body); err != nil {
				return err
			}
		}
		return nil

	case BreakStmt:
		return errBreak

	case ContinueStmt:
		return errContinue

	case HaltStmt:
		return errStop
	}
	return fmt.Errorf("script: unknown statement %T", s)
}

// evalBody evaluates a block, translating break/continue/stop into the caller.
func (e *Engine) evalBody(stmts []Stmt) error {
	for _, stmt := range stmts {
		if err := e.evalStmt(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) assign(st AssignStmt) error {
	val := e.evalExpr(st.Value)
	switch st.Op {
	case ">>":
		cur, ok := e.vars[st.Var]
		if !ok || !cur.isList {
			e.vars[st.Var] = value{isList: true, list: []string{val.str()}}
			return nil
		}
		cur.list = append(cur.list, val.str())
		e.vars[st.Var] = cur
		return nil
	default:
		e.vars[st.Var] = val
		return nil
	}
}

func (e *Engine) wait(st WaitStmt) error {
	deadline := time.Now().Add(st.Max)
	for {
		if !e.Runner.IsRunning(st.Module) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("script: wait for %s timed out", st.Module)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (e *Engine) forEach(st ForEachStmt) error {
	v := e.evalExpr(st.List)
	var items []string
	if v.isList {
		items = v.list
	} else {
		for _, part := range strings.Split(v.s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				items = append(items, part)
			}
		}
	}
	for _, item := range items {
		e.vars[st.Var] = value{s: item}
		if err := e.evalBody(st.Body); err != nil {
			if errors.Is(err, errBreak) {
				return nil
			}
			if errors.Is(err, errContinue) {
				continue
			}
			return err
		}
	}
	return nil
}

// evalExpr resolves an expression to a runtime value.
func (e *Engine) evalExpr(x Expr) value {
	switch ex := x.(type) {
	case StringLit:
		return value{s: e.interpolate(ex)}
	case NumLit:
		return value{s: ex.Value}
	case IdentExpr:
		if v, ok := e.vars[ex.Name]; ok {
			return v
		}
		return value{s: ""}
	case PropExpr:
		return e.resolveProp(ex.Path)
	case ListExpr:
		var out []string
		for _, item := range ex.Items {
			out = append(out, e.evalExpr(item).str())
		}
		return value{isList: true, list: out}
	}
	return value{}
}

// interpolate builds the final string from the segments of a StringLit.
func (e *Engine) interpolate(lit StringLit) string {
	var b strings.Builder
	for _, seg := range lit.Segs {
		switch {
		case seg.Var != "":
			b.WriteString(e.varValue(seg.Var).str())
		case seg.Prop != "":
			b.WriteString(e.resolveProp(seg.Prop).str())
		default:
			b.WriteString(seg.Text)
		}
	}
	return b.String()
}

func (e *Engine) varValue(name string) value {
	// $(list.size) resolves to the length of a list variable.
	if strings.HasSuffix(name, ".size") {
		base := name[:len(name)-len(".size")]
		if v, ok := e.vars[base]; ok {
			if v.isList {
				return value{s: strconv.Itoa(len(v.list))}
			}
			return value{s: strconv.Itoa(len(v.s))}
		}
	}
	if v, ok := e.vars[name]; ok {
		return v
	}
	return value{}
}

// resolveProp handles $(path): script variables take priority when the path
// starts with an underscore, otherwise the Runner resolves a session property.
func (e *Engine) resolveProp(path string) value {
	if strings.HasPrefix(path, "_") {
		return e.varValue(path)
	}
	if e.Runner != nil {
		if s, ok := e.Runner.Prop(path); ok {
			return value{s: s}
		}
	}
	return value{}
}

// evalCond evaluates a condition expression.
func (e *Engine) evalCond(c Cond) bool {
	switch cond := c.(type) {
	case BoolCond:
		return cond.Value
	case CmpCond:
		return cmpValues(cond.Op, e.evalExpr(cond.L), e.evalExpr(cond.R))
	case ContainsCond:
		l, r := e.evalExpr(cond.L), e.evalExpr(cond.R)
		if l.isList {
			for _, item := range l.list {
				if item == r.str() {
					return true
				}
			}
			return false
		}
		return strings.Contains(l.str(), r.str())
	case RunningCond:
		mod := e.evalExpr(cond.Module).str()
		running := e.Runner != nil && e.Runner.IsRunning(mod)
		if cond.Negate {
			return !running
		}
		return running
	case NotCond:
		return !e.evalCond(cond.C)
	case AndCond:
		return e.evalCond(cond.L) && e.evalCond(cond.R)
	case OrCond:
		return e.evalCond(cond.L) || e.evalCond(cond.R)
	}
	return false
}

// cmpValues compares two values; numeric when both parse as numbers.
func cmpValues(op string, l, r value) bool {
	ls, rs := l.str(), r.str()
	if ln, lok := strconv.ParseFloat(ls, 64); lok == nil {
		if rn, rok := strconv.ParseFloat(rs, 64); rok == nil {
			return cmpNums(op, ln, rn)
		}
	}
	switch op {
	case "==":
		return ls == rs
	case "!=":
		return ls != rs
	case "<":
		return ls < rs
	case ">":
		return ls > rs
	case "<=":
		return ls <= rs
	case ">=":
		return ls >= rs
	}
	return false
}

func cmpNums(op string, l, r float64) bool {
	switch op {
	case "==":
		return l == r
	case "!=":
		return l != r
	case "<":
		return l < r
	case ">":
		return l > r
	case "<=":
		return l <= r
	case ">=":
		return l >= r
	}
	return false
}

// evalOpts flattens the inline "key value key value" tokens of a StartStmt.
func evalOpts(e *Engine, exprs []Expr) (map[string]string, error) {
	opts := map[string]string{}
	for i := 0; i+1 < len(exprs); i += 2 {
		key := e.evalExpr(exprs[i]).str()
		val := e.evalExpr(exprs[i+1]).str()
		if key == "" {
			return nil, fmt.Errorf("script: module option key missing before %q", val)
		}
		opts[key] = val
	}
	if len(exprs)%2 != 0 {
		return nil, fmt.Errorf("script: module options must come in key/value pairs")
	}
	return opts, nil
}

// Describe renders a parsed program as an English summary. It powers the
// `toha3ee build <file>` dry-run so users can review a script before running.
func Describe(prog *Program) []string {
	var out []string
	var walk func(stmts []Stmt, depth int)
	indent := func(depth int) string { return strings.Repeat("  ", depth) }
	walk = func(stmts []Stmt, depth int) {
		for _, s := range stmts {
			switch st := s.(type) {
			case SetStmt:
				out = append(out, fmt.Sprintf("%sset %s = %s", indent(depth), st.Key, exprText(st.Value)))
			case GetStmt:
				out = append(out, fmt.Sprintf("%s%s <- get %s", indent(depth), st.Var, st.Key))
			case AssignStmt:
				out = append(out, fmt.Sprintf("%s%s %s %s", indent(depth), st.Var, st.Op, exprText(st.Value)))
			case StartStmt:
				out = append(out, fmt.Sprintf("%srun %s", indent(depth), st.ID))
			case StopStmt:
				out = append(out, fmt.Sprintf("%sstop %s", indent(depth), st.ID))
			case WaitStmt:
				out = append(out, fmt.Sprintf("%swait for %s to finish", indent(depth), st.Module))
			case SleepStmt:
				out = append(out, fmt.Sprintf("%ssleep %s second(s)", indent(depth), exprText(st.Seconds)))
			case EchoStmt:
				out = append(out, fmt.Sprintf("%sprint %s", indent(depth), exprText(st.Value)))
			case ShowStmt:
				out = append(out, fmt.Sprintf("%sshow module %s", indent(depth), st.ID))
			case ExecStmt:
				out = append(out, fmt.Sprintf("%sexec %s", indent(depth), st.Raw))
			case ReportStmt:
				out = append(out, fmt.Sprintf("%swrite report to %s", indent(depth), exprText(st.Path)))
			case IfStmt:
				out = append(out, fmt.Sprintf("%sif %s", indent(depth), condText(st.Cond)))
				walk(st.Then, depth+1)
				if len(st.Else) > 0 {
					out = append(out, indent(depth)+"else")
					walk(st.Else, depth+1)
				}
				out = append(out, indent(depth)+"end")
			case ForEachStmt:
				out = append(out, fmt.Sprintf("%sfor each %s in %s", indent(depth), st.Var, exprText(st.List)))
				walk(st.Body, depth+1)
				out = append(out, indent(depth)+"end")
			case RepeatStmt:
				out = append(out, fmt.Sprintf("%srepeat %s times", indent(depth), exprText(st.N)))
				walk(st.Body, depth+1)
				out = append(out, indent(depth)+"end")
			case WhileStmt:
				out = append(out, fmt.Sprintf("%swhile %s", indent(depth), condText(st.Cond)))
				walk(st.Body, depth+1)
				out = append(out, indent(depth)+"end")
			case BreakStmt:
				out = append(out, indent(depth)+"break")
			case ContinueStmt:
				out = append(out, indent(depth)+"continue")
			case HaltStmt:
				out = append(out, indent(depth)+"stop the script")
			}
		}
	}
	walk(prog.Stmts, 0)
	return out
}

func exprText(e Expr) string {
	switch v := e.(type) {
	case StringLit:
		return v.strText()
	case NumLit:
		return v.Value
	case IdentExpr:
		return v.Name
	case PropExpr:
		return "$(" + v.Path + ")"
	case ListExpr:
		parts := make([]string, 0, len(v.Items))
		for _, it := range v.Items {
			parts = append(parts, exprText(it))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return "?"
}

func (s StringLit) strText() string {
	var b strings.Builder
	for _, seg := range s.Segs {
		switch {
		case seg.Var != "":
			b.WriteString("$(" + seg.Var + ")")
		case seg.Prop != "":
			b.WriteString("$(" + seg.Prop + ")")
		default:
			b.WriteString(seg.Text)
		}
	}
	return strconv.Quote(b.String())
}

func condText(c Cond) string {
	switch v := c.(type) {
	case BoolCond:
		return strconv.FormatBool(v.Value)
	case CmpCond:
		return fmt.Sprintf("%s %s %s", exprText(v.L), v.Op, exprText(v.R))
	case ContainsCond:
		return fmt.Sprintf("%s contains %s", exprText(v.L), exprText(v.R))
	case RunningCond:
		neg := ""
		if v.Negate {
			neg = "not "
		}
		return fmt.Sprintf("%s is %srunning", exprText(v.Module), neg)
	case NotCond:
		return "not " + condText(v.C)
	case AndCond:
		return condText(v.L) + " && " + condText(v.R)
	case OrCond:
		return condText(v.L) + " || " + condText(v.R)
	}
	return "?"
}

// numFromValue extracts a number from a runtime value.
func numFromValue(v value) (float64, bool) {
	if v.isList {
		return 0, false
	}
	n, err := strconv.ParseFloat(v.s, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// sortedVars returns the script variable names in deterministic order (tests,
// debug).
func (e *Engine) sortedVars() []string {
	names := make([]string, 0, len(e.vars))
	for n := range e.vars {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
