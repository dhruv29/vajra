package egress

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event records one connection decision made by the gate.
type Event struct {
	Time    time.Time `json:"time"`
	Method  string    `json:"method"`
	Target  string    `json:"target"`
	Allowed bool      `json:"allowed"`
	Reason  string    `json:"reason,omitempty"`
}

// Sink receives audit events. Implementations must be safe for concurrent use.
type Sink interface {
	Record(Event)
}

// JSONLSink writes one JSON object per line.
type JSONLSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLSink writes events to w.
func NewJSONLSink(w io.Writer) *JSONLSink {
	return &JSONLSink{enc: json.NewEncoder(w)}
}

// Record writes e. A write failure cannot be reported to the caller of the
// proxied request, so it is dropped here; the proxy still enforces the policy.
func (s *JSONLSink) Record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(e)
}

// MemorySink keeps events in memory, for tests and for run summaries.
type MemorySink struct {
	mu     sync.Mutex
	events []Event
}

// Record stores e.
func (s *MemorySink) Record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// Events returns a copy of everything recorded so far.
func (s *MemorySink) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}
