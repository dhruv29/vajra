package har

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// errTooLarge is returned by capReader once the input passes its limit.
var errTooLarge = errors.New("input is over the byte limit")

// capReader passes through at most limit bytes and fails, rather than
// pretending the file ended, when there is more. Truncating silently would
// turn an oversized file into a confusing syntax error, or worse, a partial
// import that looks complete.
type capReader struct {
	r         io.Reader
	remaining int64 // limit+1: reading the extra byte proves the file is too big
}

func newCapReader(r io.Reader, limit int64) *capReader {
	return &capReader{r: r, remaining: limit + 1}
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if c.remaining <= 0 {
		return n, errTooLarge
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return n, &readError{err: err}
	}
	return n, err
}

// readError marks a failure of the underlying reader, so it is not reported
// as a fault in the file.
type readError struct{ err error }

func (e *readError) Error() string { return e.err.Error() }
func (e *readError) Unwrap() error { return e.err }

// decodeEntries streams the file and calls visit with each element of
// log.entries, undecoded. Only one entry is held in memory at a time. Any
// other key, at the top level or inside "log", is skipped.
func decodeEntries(r io.Reader, limit int64, visit func(json.RawMessage)) error {
	dec := json.NewDecoder(newCapReader(r, limit))
	if err := expectDelim(dec, '{'); err != nil {
		return decodeError(err, limit)
	}
	foundLog := false
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return decodeError(err, limit)
		}
		if key != "log" {
			if err := skipValue(dec); err != nil {
				return decodeError(err, limit)
			}
			continue
		}
		foundLog = true
		if err := decodeLog(dec, visit); err != nil {
			return decodeError(err, limit)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return decodeError(err, limit)
	}
	if !foundLog {
		return errors.New("har: not a HAR file: there is no \"log\" object")
	}
	return nil
}

// decodeLog walks the "log" object and hands each entry to visit.
func decodeLog(dec *json.Decoder, visit func(json.RawMessage)) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return err
		}
		if key != "entries" {
			if err := skipValue(dec); err != nil {
				return err
			}
			continue
		}
		if err := decodeEntryArray(dec, visit); err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

// decodeEntryArray reads "entries", which may be an array or null.
func decodeEntryArray(dec *json.Decoder, visit func(json.RawMessage)) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("\"entries\" is %v, not an array", tok)
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		visit(raw)
	}
	return expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return fmt.Errorf("found %v where %q was expected", tok, want)
	}
	return nil
}

func readKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("found %v where an object key was expected", tok)
	}
	return key, nil
}

// skipValue reads past one value. It is held whole for a moment, which the
// byte limit already bounds.
func skipValue(dec *json.Decoder) error {
	var skip json.RawMessage
	return dec.Decode(&skip)
}

// decodeError gives a decoding failure one clear, prefixed message.
func decodeError(err error, limit int64) error {
	var readErr *readError
	switch {
	case errors.As(err, &readErr):
		return fmt.Errorf("har: reading recording: %w", readErr.err)
	case errors.Is(err, errTooLarge):
		return fmt.Errorf("har: recording is larger than the %d-byte limit", limit)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("har: malformed JSON: unexpected end of input")
	default:
		return fmt.Errorf("har: malformed JSON: %w", err)
	}
}
