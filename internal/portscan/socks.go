package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// ErrRefused means the gate would not allow the connection: the address is
// outside the scope policy.
var ErrRefused = errors.New("portscan: the egress gate refused the connection")

const (
	socksVersion       = 0x05
	socksNoAuth        = 0x00
	socksConnect       = 0x01
	socksDomain        = 0x03
	socksReplyOK       = 0x00
	socksReplyNotAllow = 0x02
	maxDomainLength    = 255
)

// SOCKS5Dialer returns a Dialer that connects through the SOCKS5 front end of
// the egress gate at proxyAddr, and the function that recognises a refusal.
// Every target is sent as a name, so the gate does the resolving and applies
// its own address checks.
func SOCKS5Dialer(proxyAddr string) (Dialer, func(error) bool) {
	dial := func(ctx context.Context, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("portscan: %w", err)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || len(host) == 0 || len(host) > maxDomainLength {
			return nil, fmt.Errorf("portscan: address %q cannot be sent to the gate", address)
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("portscan: reach the gate: %w", err)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if err := socksHandshake(conn, host, uint16(port)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return dial, func(err error) bool { return errors.Is(err, ErrRefused) }
}

// socksHandshake asks the gate to connect to host:port.
func socksHandshake(conn io.ReadWriter, host string, port uint16) error {
	if _, err := conn.Write([]byte{socksVersion, 1, socksNoAuth}); err != nil {
		return fmt.Errorf("portscan: gate handshake: %w", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || method[0] != socksVersion || method[1] != socksNoAuth {
		return errors.New("portscan: the gate did not accept the handshake")
	}
	request := append([]byte{socksVersion, socksConnect, 0x00, socksDomain, byte(len(host))}, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("portscan: gate request: %w", err)
	}
	// The reply to a CONNECT is ten bytes: the gate always answers with an
	// IPv4 bind address.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("portscan: gate reply: %w", err)
	}
	switch reply[1] {
	case socksReplyOK:
		return nil
	case socksReplyNotAllow:
		return ErrRefused
	default:
		return fmt.Errorf("portscan: not reachable (gate reply %d)", reply[1])
	}
}
