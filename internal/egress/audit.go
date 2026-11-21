package egress

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Outcome is what the gate did with a connection.
type Outcome string

const (
	// Allowed means the policy permitted the connection and it was attempted.
	Allowed Outcome = "allowed"
	// Denied means the policy refused it; nothing was sent.
	Denied Outcome = "denied"
	// Failed means the policy permitted it but the target could not be
	// reached or did not answer.
	Failed Outcome = "failed"
)

// Event records one connection decision made by the gate.
type Event struct {
	Time   time.Time `json:"time"`
	Method string    `json:"method"`
	Target string    `json:"target"`
	// Allowed is false only when the policy refused the connection.
	Allowed bool    `json:"allowed"`
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason,omitempty"`
}

// Sink receives audit events. Implementations must be safe for concurrent
// use. An error means the event was not recorded; the gate then refuses to
// forward, because nothing may pass unaudited.
type Sink interface {
	Record(Event) error
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

// Record writes e.
func (s *JSONLSink) Record(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(e)
}

// MemorySink keeps events in memory, for tests and for run summaries.
type MemorySink struct {
	mu     sync.Mutex
	events []Event
}

// Record stores e.
func (s *MemorySink) Record(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// Events returns a copy of everything recorded so far.
func (s *MemorySink) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}
