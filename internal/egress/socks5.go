package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/dhruv29/vajra/internal/scope"
)

// Protocol constants from RFC 1928.
const (
	socksVersion = 0x05

	socksNoAuth       = 0x00
	socksNoAcceptable = 0xFF

	socksConnect = 0x01

	socksIPv4   = 0x01
	socksDomain = 0x03
	socksIPv6   = 0x04

	socksSucceeded           = 0x00
	socksGeneralFailure      = 0x01
	socksNotAllowed          = 0x02
	socksHostUnreachable     = 0x04
	socksConnectionRefused   = 0x05
	socksCommandNotSupported = 0x07
	socksAddressNotSupported = 0x08
)

const (
	// socksMethod is the Method of every audit event this front end writes.
	socksMethod = "SOCKS5"
	// socksHandshakeTimeout bounds the time from accepting a connection to
	// having read its whole request, so a silent client cannot hold a
	// connection open. It also bounds each reply write.
	socksHandshakeTimeout = 15 * time.Second
)

var errSOCKSVersion = errors.New("egress: not a SOCKS5 client")

// SOCKS5 is a SOCKS5 server (RFC 1928) that only supports what the gate
// needs: no authentication, the CONNECT command, and IPv4, IPv6 or
// domain-name targets. It exists so that tools which speak raw TCP are held
// to the same scope policy as HTTP clients: every target goes through the
// Guard, which checks, resolves and dials it.
type SOCKS5 struct {
	guard            *Guard
	sink             Sink
	now              func() time.Time
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	tunnelIdle       time.Duration
}

// NewSOCKS5 builds a SOCKS5 front end around guard. Every decision is sent
// to sink.
func NewSOCKS5(guard *Guard, sink Sink) (*SOCKS5, error) {
	if guard == nil {
		return nil, errors.New("egress: a guard is required")
	}
	if sink == nil {
		return nil, errors.New("egress: an audit sink is required")
	}
	return &SOCKS5{
		guard:            guard,
		sink:             sink,
		now:              time.Now,
		handshakeTimeout: socksHandshakeTimeout,
		dialTimeout:      dialTimeout,
		tunnelIdle:       tunnelIdleTimeout,
	}, nil
}

// Serve accepts connections until the listener is closed or ctx is
// cancelled; it returns nil on a clean stop. Cancelling ctx closes the
// listener and every open connection. Serve returns only after every
// connection it accepted has finished, so nothing outlives it.
func (s *SOCKS5) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	open := &connSet{conns: map[net.Conn]struct{}{}}
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		open.closeAll()
	})
	defer stop()

	var wg sync.WaitGroup
	acceptErr := s.accept(ctx, listener, open, &wg)
	clean := ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed)
	if !clean {
		cancel() // the gate is going down: do not leave tunnels behind it
	}
	wg.Wait()
	if clean {
		return nil
	}
	return fmt.Errorf("egress: socks5 accept: %w", acceptErr)
}

// accept hands each connection to its own goroutine and returns the error
// that ended the loop.
func (s *SOCKS5) accept(ctx context.Context, listener net.Listener, open *connSet, wg *sync.WaitGroup) error {
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		if !open.add(client) {
			_ = client.Close() // accepted while shutting down
			continue
		}
		wg.Go(func() {
			defer open.remove(client)
			defer client.Close()
			s.handle(ctx, client)
		})
	}
}

// connSet tracks the client connections that are open, so shutdown can close
// them instead of waiting for their peers.
type connSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// add reports false once the set has been closed.
func (c *connSet) add(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.conns[conn] = struct{}{}
	return true
}

func (c *connSet) remove(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.conns, conn)
}

func (c *connSet) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for conn := range c.conns {
		_ = conn.Close()
	}
}

// handle runs one client connection: handshake, decision, then relay.
func (s *SOCKS5) handle(ctx context.Context, client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(s.handshakeTimeout))
	if err := negotiate(client); err != nil {
		return
	}
	target, refusal, err := readRequest(client)
	if err != nil {
		return
	}
	if refusal != socksSucceeded {
		s.reply(client, refusal)
		return
	}
	s.connect(ctx, client, target)
}

// negotiate reads the client's greeting and selects "no authentication",
// the only method the gate offers. Exactly the bytes the greeting declares
// are read, and no more.
func negotiate(client net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return errSOCKSVersion
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == socksNoAuth {
			_, err := client.Write([]byte{socksVersion, socksNoAuth})
			return err
		}
	}
	_, _ = client.Write([]byte{socksVersion, socksNoAcceptable})
	return errors.New("egress: the client offered no supported authentication method")
}

// readRequest reads one request and returns its target as "host:port". A
// non-zero refusal is the reply code for a request the gate will not serve;
// an error means the connection should simply be closed.
//
// The address is read before an unsupported command is refused, so the
// refusal is not lost to a connection reset caused by closing with the rest
// of the request unread. It is still bounded: at most a length-prefixed name.
func readRequest(r io.Reader) (target string, refusal byte, err error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", 0, err
	}
	version, command, reserved, addressType := header[0], header[1], header[2], header[3]
	if version != socksVersion {
		return "", 0, errSOCKSVersion
	}
	host, known, err := readHost(r, addressType)
	if err != nil {
		return "", 0, err
	}
	var port [2]byte
	if known {
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return "", 0, err
		}
	}
	switch {
	case command != socksConnect:
		return "", socksCommandNotSupported, nil
	case !known:
		return "", socksAddressNotSupported, nil
	case reserved != 0 || host == "":
		return "", socksGeneralFailure, nil
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), 0, nil
}

// readHost reads the address of a request. known is false for an address
// type the gate does not support, whose length cannot be told.
func readHost(r io.Reader, addressType byte) (host string, known bool, err error) {
	switch addressType {
	case socksIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", false, err
		}
		return netip.AddrFrom4(raw).String(), true, nil
	case socksIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return "", false, err
		}
		return netip.AddrFrom16(raw).String(), true, nil
	case socksDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", false, err
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", false, err
		}
		return string(name), true, nil
	default:
		return "", false, nil
	}
}

// connect asks the guard for the target and, if the policy allows it and the
// decision could be audited, relays between the client and the target.
func (s *SOCKS5) connect(ctx context.Context, client net.Conn, target string) {
	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout)
	upstream, err := s.guard.DialContext(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		s.refuse(client, target, err)
		return
	}
	defer upstream.Close()
	// The decision is logged before the client is told the tunnel is open,
	// and nothing is relayed if it could not be logged.
	if !s.record(target, Allowed, "") {
		s.reply(client, socksGeneralFailure)
		return
	}
	if !s.reply(client, socksSucceeded) {
		return
	}
	// Reads so far were exact, so the client has no buffered bytes to replay.
	tunnel(client, client, upstream, s.tunnelIdle)
}

// refuse records why a connection did not go through and answers the client:
// "not allowed by ruleset" when the policy denied it, otherwise a code that
// says the target could not be reached.
func (s *SOCKS5) refuse(client net.Conn, target string, err error) {
	if scope.IsDenied(err) {
		s.record(target, Denied, err.Error())
		s.reply(client, socksNotAllowed)
		return
	}
	s.record(target, Failed, err.Error())
	if errors.Is(err, syscall.ECONNREFUSED) {
		s.reply(client, socksConnectionRefused)
		return
	}
	s.reply(client, socksHostUnreachable)
}

// record writes one audit event and reports whether it was written.
func (s *SOCKS5) record(target string, outcome Outcome, reason string) bool {
	return s.sink.Record(Event{
		Time: s.now().UTC(), Method: socksMethod, Target: target,
		Allowed: outcome != Denied, Outcome: outcome, Reason: reason,
	}) == nil
}

// reply sends a reply with the given code and reports whether it was sent.
// The bound address is always 0.0.0.0:0: the gate does not reveal which
// address it connected from. The deadline is renewed first because the
// handshake deadline may have passed while the target was being dialled.
func (s *SOCKS5) reply(client net.Conn, code byte) bool {
	_ = client.SetDeadline(time.Now().Add(s.handshakeTimeout))
	_, err := client.Write([]byte{socksVersion, code, 0x00, socksIPv4, 0, 0, 0, 0, 0, 0})
	return err == nil
}
