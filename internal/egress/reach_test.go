package egress

import (
	"strings"
	"testing"
)

const auditLog = `vajra: egress gate listening on [::]:3128
{"time":"2026-11-21T19:54:40Z","method":"GET","target":"app.test:80","allowed":true}
{"time":"2026-11-21T19:54:41Z","method":"GET","target":"app.test:80","allowed":true}
{"time":"2026-11-21T19:54:42Z","method":"CONNECT","target":"evil.test:443","allowed":false,"reason":"old reason"}
{"time":"2026-11-21T19:54:43Z","method":"CONNECT","target":"evil.test:443","allowed":false,"reason":"host is not in scope"}
{"time":"2026-11-21T19:54:44Z","method":"GET","target":"api.app.test:80","allowed":true}
{"time":"2026-11-21T19:54:45Z","method":"GET","target":"169.254.169.254:80","allowed":false,"reason":"never a target"}
{"not":"an event"}

`

func TestReadEventsSkipsNonEventLines(t *testing.T) {
	events, err := ReadEvents(strings.NewReader(auditLog))

	if err != nil || len(events) != 6 {
		t.Fatalf("events = %d, err = %v; want 6", len(events), err)
	}
	if events[2].Method != "CONNECT" || events[2].Allowed || events[0].Time.IsZero() {
		t.Fatalf("events = %+v", events[:3])
	}
	if _, err := ReadEvents(strings.NewReader(strings.Repeat("x", maxAuditLineBytes+1))); err == nil {
		t.Fatal("an oversized line was not reported")
	}
}

func TestSummarizeGroupsByTargetBusiestFirst(t *testing.T) {
	events, _ := ReadEvents(strings.NewReader(auditLog))

	reach := Summarize(events)

	if reach.AllowedTotal != 3 || reach.DeniedTotal != 3 {
		t.Fatalf("totals = %d allowed, %d denied", reach.AllowedTotal, reach.DeniedTotal)
	}
	wantAllowed := []TargetCount{{Target: "app.test:80", Count: 2}, {Target: "api.app.test:80", Count: 1}}
	if len(reach.Allowed) != 2 || reach.Allowed[0] != wantAllowed[0] || reach.Allowed[1] != wantAllowed[1] {
		t.Fatalf("allowed = %+v", reach.Allowed)
	}
	if len(reach.Denied) != 2 || reach.Denied[0] != (TargetCount{Target: "evil.test:443", Count: 2, Reason: "host is not in scope"}) {
		t.Fatalf("denied = %+v; want the latest reason and the busiest target first", reach.Denied)
	}
	empty := Summarize(nil)
	if empty.Allowed == nil || empty.Denied == nil || empty.AllowedTotal != 0 {
		t.Fatalf("empty summary = %+v; lists must be empty, not null", empty)
	}
}
