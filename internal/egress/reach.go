package egress

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

const maxAuditLineBytes = 1 << 20

// TargetCount is how often one target appears in the audit log.
type TargetCount struct {
	Target string `json:"target"`
	Count  int    `json:"count"`
	// Reason is the most recent denial reason; empty for allowed targets.
	Reason string `json:"reason,omitempty"`
}

// Reach summarises what a run touched and what it was refused.
type Reach struct {
	Allowed      []TargetCount `json:"allowed"`
	Denied       []TargetCount `json:"denied"`
	AllowedTotal int           `json:"allowed_total"`
	DeniedTotal  int           `json:"denied_total"`
}

// ReadEvents parses an audit log written by JSONLSink. Lines that are not
// audit events (for example the gate's start-up message) are skipped.
func ReadEvents(r io.Reader) ([]Event, error) {
	events := []Event{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), maxAuditLineBytes)
	for scanner.Scan() {
		var e Event
		if json.Unmarshal(scanner.Bytes(), &e) != nil || e.Target == "" {
			continue
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("egress: read audit log: %w", err)
	}
	return events, nil
}

// Summarize groups events by target, busiest first.
func Summarize(events []Event) Reach {
	allowed, denied := map[string]*TargetCount{}, map[string]*TargetCount{}
	reach := Reach{}
	for _, e := range events {
		group := denied
		if e.Allowed {
			group = allowed
			reach.AllowedTotal++
		} else {
			reach.DeniedTotal++
		}
		entry, ok := group[e.Target]
		if !ok {
			entry = &TargetCount{Target: e.Target}
			group[e.Target] = entry
		}
		entry.Count++
		if !e.Allowed {
			entry.Reason = e.Reason
		}
	}
	reach.Allowed, reach.Denied = flatten(allowed), flatten(denied)
	return reach
}

func flatten(group map[string]*TargetCount) []TargetCount {
	out := make([]TargetCount, 0, len(group))
	for _, entry := range group {
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Target < out[j].Target
	})
	return out
}
