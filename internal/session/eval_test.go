package session

import (
	"strings"
	"testing"
)

// TestEvalRunsSequenceInOrder verifies a ";"-separated one-shot sequence runs
// every command in order through the normal dispatcher.
func TestEvalRunsSequenceInOrder(t *testing.T) {
	s, buf := newTestSession(t)
	if err := s.Eval("net.show; status; net.show"); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "net.show") {
		t.Error("Eval output missing the echoed commands")
	}
	if !strings.Contains(out, "no hosts discovered") || !strings.Contains(out, "no modules running") {
		t.Errorf("Eval output missing expected command results:\n%s", out)
	}
	// net.show must come before status in the echoed command order.
	if strings.Index(out, "[>] net.show") > strings.Index(out, "[>] status") {
		t.Error("Eval did not preserve command order")
	}
}

// TestEvalSplitsOnNewlinesAndSemicolons verifies multi-line sequences and
// mixed separators are handled.
func TestEvalSplitsOnNewlinesAndSemicolons(t *testing.T) {
	s, buf := newTestSession(t)
	if err := s.Eval("net.show\n; net.show; # comment\nstatus"); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "[>]") != 3 {
		t.Errorf("expected 3 echoed commands, got:\n%s", out)
	}
}

// TestEvalOutputHasNoFormattingArtifacts is a regression test for a bug where
// -eval output corrupted values into fmt "%!s" style artifacts. Values that
// contain percent verbs and other format-punctuation must round-trip verbatim.
func TestEvalOutputHasNoFormattingArtifacts(t *testing.T) {
	s, buf := newTestSession(t)
	seq := `set net.scan.ports "80%s"; get net.scan.ports; set http.harvest.filter "tcp.%s && port 80"` + "\n" + `get http.harvest.filter`
	if err := s.Eval(seq); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "%!") || strings.Contains(out, "MISSING") {
		t.Errorf("Eval output contains fmt verb artifacts:\n%s", out)
	}
	if !strings.Contains(out, `net.scan.ports: "80%s"`) {
		t.Errorf("Eval lost the percent-bearing value verbatim:\n%s", out)
	}
}

// TestEvalPropagatesErrors verifies the sequence stops at the first failing
// command and the error surfaces.
func TestEvalPropagatesErrors(t *testing.T) {
	s, _ := newTestSession(t)
	if err := s.Eval("definitely.not.a.command"); err == nil {
		t.Error("Eval of an unknown command should error")
	} else if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEvalStopsAtFirstFailure verifies commands after a failure are not run.
func TestEvalStopsAtFirstFailure(t *testing.T) {
	s, buf := newTestSession(t)
	if err := s.Eval("net.show; definitely.not.a.command; net.show"); err == nil {
		t.Fatal("Eval should error on the unknown command")
	}
	if strings.Count(buf.String(), "[>]") != 2 {
		t.Errorf("expected the sequence to stop after the failure, got:\n%s", buf.String())
	}
}

// TestEvalEmptyAndCommentOnlyAreNoOps verifies blank, comment-only and
// separator-only sequences succeed without executing anything.
func TestEvalEmptyAndCommentOnlyAreNoOps(t *testing.T) {
	for _, seq := range []string{"", "   ", "; ;;", "# just a comment\n# another"} {
		s, buf := newTestSession(t)
		if err := s.Eval(seq); err != nil {
			t.Errorf("Eval(%q) = %v, want nil", seq, err)
		}
		if buf.Len() != 0 {
			t.Errorf("Eval(%q) produced output, want none: %q", seq, buf.String())
		}
	}
}
