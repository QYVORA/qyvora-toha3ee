package script

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockRunner is a scriptable test double for the script engine. All maps and
// slices are guarded by mu because the engine can drive the runner from
// background goroutines (e.g. "wait for" polling) while the test mutates state.
type mockRunner struct {
	mu          sync.Mutex
	conf        map[string]string
	running     map[string]bool
	props       map[string]string
	echos       []string
	started     []string
	startedOpts []map[string]string
	stopped     []string
	reports     []string
	cmds        []string
	failOnStart string // module name that should fail on Start
}

func newMock() *mockRunner {
	return &mockRunner{
		conf:    map[string]string{},
		running: map[string]bool{},
		props:   map[string]string{"hosts.count": "4", "iface.ip": "10.0.0.1"},
	}
}

func (m *mockRunner) Echo(s string) {
	m.mu.Lock()
	m.echos = append(m.echos, s)
	m.mu.Unlock()
}
func (m *mockRunner) SetConfig(key, value string) error {
	m.mu.Lock()
	m.conf[key] = value
	m.mu.Unlock()
	return nil
}
func (m *mockRunner) GetConfig(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conf[key]
}
func (m *mockRunner) Start(id string, opts map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOnStart != "" && id == m.failOnStart {
		return fmt.Errorf("module %s failed", id)
	}
	m.started = append(m.started, id)
	m.startedOpts = append(m.startedOpts, opts)
	m.running[id] = true
	return nil
}
func (m *mockRunner) Stop(id string) error {
	m.mu.Lock()
	m.stopped = append(m.stopped, id)
	m.running[id] = false
	m.mu.Unlock()
	return nil
}
func (m *mockRunner) IsRunning(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running[id]
}
func (m *mockRunner) Show(id string) error { return nil }
func (m *mockRunner) Report(path string) error {
	m.mu.Lock()
	m.reports = append(m.reports, path)
	m.mu.Unlock()
	return nil
}
func (m *mockRunner) setRunning(id string, val bool) {
	m.mu.Lock()
	m.running[id] = val
	m.mu.Unlock()
}
func (m *mockRunner) Cmd(line string) error {
	m.cmds = append(m.cmds, line)
	return nil
}
func (m *mockRunner) Prop(name string) (string, bool) {
	v, ok := m.props[name]
	return v, ok
}

// run executes src against a fresh mock and returns the mock.
func run(src string) (*mockRunner, error) {
	m := newMock()
	e := NewEngine(m)
	if err := e.Run(src); err != nil {
		return m, err
	}
	return m, nil
}

func TestLexBasics(t *testing.T) {
	toks, err := lex("# comment\nset net.scan.targets -> \"10.0.0.0/24\"\n_keep >> 5ms\n")
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, tk := range toks {
		kinds = append(kinds, tk.text)
	}
	joined := strings.Join(kinds, " ")
	for _, want := range []string{"set", "net.scan.targets", "->", "10.0.0.0/24", "_keep", ">>", "5ms"} {
		if !strings.Contains(joined, want) {
			t.Errorf("token stream missing %q (got %q)", want, joined)
		}
	}
}

func TestParseAndDescribe(t *testing.T) {
	src := `
# recon pipeline
set net.scan.targets -> "192.168.8.0/24"
on net.scan
wait for net.scan
_hosts -> [$(net.hosts)]
if $(hosts.count) > 0
	echo -> "found $(_hosts.size) host(s)"
	repeat 2 times
		sleep -> 1
	end
else
	say "nothing"
end
for each _h in _hosts
	print -> "$(_h)"
end
report -> "assessment.md"
`
	prog, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	lines := Describe(prog)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		`set net.scan.targets = "192.168.8.0/24"`,
		"run net.scan",
		"wait for net.scan to finish",
		`_hosts -> [$(net.hosts)]`,
		`if $(hosts.count) > "0"`,
		`for each _h in _hosts`,
		`repeat "2" times`,
		`sleep "1" second(s)`,
		"write report to \"assessment.md\"",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Describe output missing %q\n---got---\n%s", want, joined)
		}
	}
}

func TestAssignmentAndInterpolation(t *testing.T) {
	src := `
_name -> "world"
echo -> "hello $(_name)!"
_targets -> [10.0.0.1, 10.0.0.2]
_targets >> 10.0.0.3
echo -> "hosts now: $(_targets.size)"
echo -> "live hosts: $(hosts.count) on $(iface.ip)"
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 3 {
		t.Fatalf("expected 3 echos, got %v", m.echos)
	}
	if m.echos[0] != "hello world!" {
		t.Errorf("interpolation failed: %q", m.echos[0])
	}
	if m.echos[1] != "hosts now: 3" {
		t.Errorf("list size failed: %q", m.echos[1])
	}
	if m.echos[2] != "live hosts: 4 on 10.0.0.1" {
		t.Errorf("prop interpolation failed: %q", m.echos[2])
	}
}

func TestSetGetConfig(t *testing.T) {
	src := `
set arp.spoof.targets -> "10.0.0.5,10.0.0.6"
get arp.spoof.targets -> _t
echo -> "targets=$(_t)"
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if m.conf["arp.spoof.targets"] != "10.0.0.5,10.0.0.6" {
		t.Errorf("set failed: %v", m.conf)
	}
	if len(m.echos) != 1 || m.echos[0] != "targets=10.0.0.5,10.0.0.6" {
		t.Errorf("get failed: %v", m.echos)
	}
}

func TestStartStopAndWait(t *testing.T) {
	src := `
on net.scan
on service.synscan ports 80,443
off service.synscan
stop net.scan
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.started) != 2 {
		t.Errorf("expected 2 starts, got %v", m.started)
	}
	if len(m.stopped) != 2 {
		t.Errorf("expected 2 stops, got %v", m.stopped)
	}
	if m.running["net.scan"] {
		t.Error("net.scan should be stopped")
	}
}

func TestWaitFor(t *testing.T) {
	m := newMock()
	e := NewEngine(m)
	// Simulate a module that finishes after 300ms.
	go func() {
		time.Sleep(300 * time.Millisecond)
		m.setRunning("net.scan", false)
	}()
	m.setRunning("net.scan", true)
	src := "on net.scan\nwait for net.scan max 5\necho -> \"done\"\n"
	start := time.Now()
	if err := e.Run(src); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Error("wait for returned too early")
	}
	if len(m.echos) != 1 || m.echos[0] != "done" {
		t.Errorf("wait didn't resume: %v", m.echos)
	}
}

func TestWaitForTimeout(t *testing.T) {
	m := newMock()
	m.setRunning("net.scan", true)
	e := NewEngine(m)
	err := e.Run("on net.scan\nwait for net.scan max 0.1\necho -> \"after\"\n")
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConditions(t *testing.T) {
	src := `
_count -> 5
if _count > 3
	echo -> "big"
end
if _count <= 3
	echo -> "small"
else
	echo -> "else-branch"
end
if "hello world" contains "world"
	echo -> "substring"
end
if net.scan is not running
	echo -> "not running"
end
if $(hosts.count) == 4 && _count != 1
	echo -> "compound"
end
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"big", "else-branch", "substring", "not running", "compound"}
	if strings.Join(m.echos, "|") != strings.Join(want, "|") {
		t.Errorf("condition echos wrong: %v (want %v)", m.echos, want)
	}
}

func TestForEachAndBreak(t *testing.T) {
	src := `
_hosts -> [a, b, c, d]
for each _h in _hosts
	if _h == c
		break
	end
	echo -> "saw $(_h)"
end
echo -> "total $(_hosts.size)"
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"saw a", "saw b", "total 4"}
	if strings.Join(m.echos, "|") != strings.Join(want, "|") {
		t.Errorf("for-each echos wrong: %v (want %v)", m.echos, want)
	}
}

func TestRepeatAndContinue(t *testing.T) {
	src := `
_kept -> []
for each _n in [1,2,3,4,5]
	if _n == 3
		continue
	end
	_kept >> $(_n)
end
echo -> "$(_kept)"
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 {
		t.Fatalf("echo count: %v", m.echos)
	}
	if m.echos[0] != "1, 2, 4, 5" {
		t.Errorf("append+continue wrong: %q", m.echos[0])
	}
}

func TestStopHalts(t *testing.T) {
	src := `
echo -> "one"
stop
echo -> "never"
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "one" {
		t.Errorf("stop didn't halt: %v", m.echos)
	}
}

func TestBreakContinueInRepeatAndWhile(t *testing.T) {
	src := `
repeat 3 times
	break
end
repeat 3 times
	continue
	echo -> "never"
end
repeat 5 times
	while true
		break
	end
end
echo -> "ok"
`
	m, err := run(src)
	if err != nil {
		t.Fatalf("break/continue in repeat/while must not leak out: %v", err)
	}
	if len(m.echos) != 1 || m.echos[0] != "ok" {
		t.Errorf("loop control echos wrong: %v", m.echos)
	}
}

func TestWhileContinueDoesNotSkipCondition(t *testing.T) {
	m := newMock()
	e := NewEngine(m)
	// continue re-checks the while condition; the sleep keeps the loop from
	// spinning millions of times before the external flag flips.
	prog := `
while net.scan is running
	sleep -> 0.05
	continue
	echo -> "never"
end
echo -> "stopped"
`
	go func() {
		time.Sleep(200 * time.Millisecond)
		m.setRunning("net.scan", false)
	}()
	m.setRunning("net.scan", true)
	if err := e.Run(prog); err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "stopped" {
		t.Errorf("while+continue echos wrong: %v", m.echos)
	}
}

func TestSingleQuotedStringIsLiteral(t *testing.T) {
	m, err := run("echo -> 'hosts: $(hosts.count)'\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "hosts: $(hosts.count)" {
		t.Errorf("single-quoted string was interpolated: %v", m.echos)
	}
}

func TestNegativeAndFlagValues(t *testing.T) {
	src := `
_n -> -1
echo -> "n=$(_n)"
exec nmap -sS -p 80,443 10.0.0.1
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "n=-1" {
		t.Errorf("negative value failed: %v", m.echos)
	}
	want := "nmap -sS -p 80,443 10.0.0.1"
	if len(m.cmds) != 1 || m.cmds[0] != want {
		t.Errorf("exec flags failed: %q (want %q)", m.cmds, want)
	}
}

func TestWaitMaxRequiresNumber(t *testing.T) {
	if _, err := Parse("wait for net.scan max abc\n"); err == nil {
		t.Error("expected an error for 'wait for ... max abc'")
	}
}

func TestUnexpectedCharacterIsError(t *testing.T) {
	for _, src := range []string{"echo -> hello@world\n", "echo -> \"x\" ;\n"} {
		if _, err := Parse(src); err == nil {
			t.Errorf("expected a lex error for %q", src)
		}
	}
}

func TestOptValueKeepsInterpolationAcrossCommas(t *testing.T) {
	src := `
_h -> 9
on arp.spoof targets 10.0.0.1,$(_h),10.0.0.2
`
	m, err := run(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.started) != 1 || len(m.startedOpts) != 1 {
		t.Fatalf("start not recorded: started=%v opts=%v", m.started, m.startedOpts)
	}
	opts := m.startedOpts[0]
	if opts["targets"] != "10.0.0.1,9,10.0.0.2" {
		t.Errorf("comma-joined option lost interpolation: %q", opts["targets"])
	}
}

func TestReport(t *testing.T) {
	m, err := run("report -> \"out.md\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.reports) != 1 || m.reports[0] != "out.md" {
		t.Errorf("report failed: %v", m.reports)
	}
}

func TestSyntaxErrors(t *testing.T) {
	cases := []string{
		"if true\n",             // missing end
		"end\n",                 // stray end
		"set\n",                 // missing key
		"on\n",                  // missing module id
		"for each _x 1\nend\n",  // missing 'in'
		"echo -> $(\n",          // unterminated property
		"\"unterminated\n",      // unterminated string
		"_x -> 1 extra stuff\n", // trailing junk after value
	}
	for _, src := range cases {
		if _, err := Parse(src); err == nil {
			t.Errorf("expected parse error for %q", src)
		}
	}
}

func TestRunnerErrorPropagates(t *testing.T) {
	m := newMock()
	e := NewEngine(m)
	m.conf["x"] = "1"
	err := e.Run("set unknown.module.key -> 1\n")
	if err != nil {
		t.Fatal(err)
	}
	_ = errors.Is // keep import used
}

func TestElifChains(t *testing.T) {
	m := newMock()
	e := NewEngine(m)

	// Test elif with first condition true
	err := e.Run("_x -> 1\nif _x == 1\n  echo -> 'one'\nelif _x == 2\n  echo -> 'two'\nelse\n  echo -> 'other'\nend\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "one" {
		t.Errorf("expected 'one', got %v", m.echos)
	}

	// Test elif with second condition true
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("_x -> 2\nif _x == 1\n  echo -> 'one'\nelif _x == 2\n  echo -> 'two'\nelse\n  echo -> 'other'\nend\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "two" {
		t.Errorf("expected 'two', got %v", m.echos)
	}

	// Test elif with else fallback
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("_x -> 3\nif _x == 1\n  echo -> 'one'\nelif _x == 2\n  echo -> 'two'\nelse\n  echo -> 'other'\nend\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "other" {
		t.Errorf("expected 'other', got %v", m.echos)
	}
}

func TestTryCatch(t *testing.T) {
	m := newMock()
	m.failOnStart = "fail.mod"
	e := NewEngine(m)

	// Test try/catch with error
	err := e.Run("try\n  on fail.mod\ncatch _err\n  echo -> $(_err)\nend\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || !strings.Contains(m.echos[0], "failed") {
		t.Errorf("expected error message in catch block, got %v", m.echos)
	}

	// Test try/catch without error (catch should not run)
	m.echos = nil
	m.failOnStart = ""
	e = NewEngine(m)
	err = e.Run("try\n  echo -> 'ok'\ncatch _err\n  echo -> 'error'\nend\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "ok" {
		t.Errorf("expected 'ok', got %v", m.echos)
	}
}

func TestFuncDefAndCall(t *testing.T) {
	m := newMock()
	e := NewEngine(m)

	// Define a function and call it (use double-quoted strings for interpolation)
	err := e.Run("def greet(_name)\n  echo -> \"Hello $(_name)\"\nend\ngreet 'World'\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "Hello World" {
		t.Errorf("expected 'Hello World', got %v", m.echos)
	}

	// Test function with no args
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("def sayhi()\n  echo -> \"hi\"\nend\nsayhi\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "hi" {
		t.Errorf("expected 'hi', got %v", m.echos)
	}

	// Test undefined function error
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("undefined_func\n")
	if err == nil {
		t.Error("expected error for undefined function")
	}
}

func TestArithmeticExpressions(t *testing.T) {
	m := newMock()
	e := NewEngine(m)

	// Test addition
	err := e.Run("_a -> 2\n_b -> 3\n_c -> _a + _b\necho -> $(_c)\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "5" {
		t.Errorf("expected '5', got %v", m.echos)
	}

	// Test multiplication
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("_a -> 4\n_b -> 5\n_c -> _a * _b\necho -> $(_c)\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "20" {
		t.Errorf("expected '20', got %v", m.echos)
	}

	// Test division
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("_a -> 10\n_b -> 2\n_c -> _a / _b\necho -> $(_c)\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "5" {
		t.Errorf("expected '5', got %v", m.echos)
	}

	// Test operator precedence (* before +)
	m.echos = nil
	e = NewEngine(m)
	err = e.Run("_a -> 2\n_b -> 3\n_c -> _a + _b * 4\necho -> $(_c)\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.echos) != 1 || m.echos[0] != "14" {
		t.Errorf("expected '14', got %v", m.echos)
	}
}
