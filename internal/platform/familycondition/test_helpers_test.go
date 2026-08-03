package familycondition

import (
	"net"
	"time"
)

type fakeConn struct {
	local      net.Addr
	remote     net.Addr
	writeCalls int
	closeCalls int
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *fakeConn) Write(buffer []byte) (int, error) { c.writeCalls++; return len(buffer), nil }
func (c *fakeConn) Close() error                     { c.closeCalls++; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return c.local }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func routeTestConn(family Family) *fakeConn {
	if family == FamilyIPv4 {
		return &fakeConn{
			local:  &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 49152},
			remote: &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53},
		}
	}
	return &fakeConn{
		local: &net.UDPAddr{
			IP:   net.ParseIP("2001:db8::10"),
			Port: 49153,
			Zone: "test0",
		},
		remote: &net.UDPAddr{IP: net.ParseIP("2606:4700:4700::1111"), Port: 53},
	}
}

func familySequenceClock(times ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if index >= len(times) {
			panic("test clock exhausted")
		}
		value := times[index]
		index++
		return value
	}
}
