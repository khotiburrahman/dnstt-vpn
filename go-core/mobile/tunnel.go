package mobile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/flynn/noise"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
)

type SocketProtector interface {
	ProtectFd(fd int) bool
}

var (
	mu         sync.Mutex
	isRunning  bool
	cancelFunc context.CancelFunc
	localLn    net.Listener
	activeSSH  *ssh.Client
	activeSMUX *smux.Session
)

const (
	dnsttPrologue    = "dnstt 2020-04-13"
	maxNoiseChunk    = 4096
	localSocksListen = "127.0.0.1:7000"
	dnsViaSSHAddr    = "1.1.1.1:53"
)

var b32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func protectedDialer(protector SocketProtector) *net.Dialer {
	return &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				if protector != nil && !protector.ProtectFd(int(fd)) {
					protectErr = fmt.Errorf("gagal protect socket fd: %d", fd)
				}
			})
			if err != nil {
				return err
			}
			return protectErr
		},
	}
}

// StartTunnel membuka DNSTT + SSH, lalu expose SOCKS5 lokal untuk tun2socks.
func StartTunnel(
	tunFd int,
	dohURL string,
	pubKeyHex string,
	domain string,
	sshHost string,
	sshPort int,
	sshUser string,
	sshPass string,
	protector SocketProtector,
) error {
	mu.Lock()
	defer mu.Unlock()

	if isRunning {
		return errors.New("tunnel sudah berjalan")
	}

	// Tutup fd kalau gagal sebelum engine ambil alih
	fdOpen := true
	defer func() {
		if fdOpen {
			_ = syscall.Close(tunFd)
		}
	}()

	pubKey, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubKey) != 32 {
		return errors.New("public key harus 64 karakter hex (32 byte)")
	}

	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		return errors.New("domain tunnel kosong")
	}

	dohURL = strings.TrimSpace(dohURL)
	if dohURL == "" {
		return errors.New("DoH URL kosong")
	}

	sshUser = strings.TrimSpace(sshUser)
	if sshUser == "" {
		return errors.New("SSH username kosong")
	}

	sshHost = strings.TrimSpace(sshHost)
	if sshHost == "" {
		sshHost = "127.0.0.1"
	}
	if sshPort <= 0 || sshPort > 65535 {
		sshPort = 22
	}
	sshAddr := net.JoinHostPort(sshHost, strconv.Itoa(sshPort))

	ctx, cancel := context.WithCancel(context.Background())

	dialer := protectedDialer(protector)
	httpClient := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     60 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}

	pConn, err := newDnsttPacketConn(ctx, httpClient, dohURL, domain)
	if err != nil {
		cancel()
		return err
	}

	kcpConn, err := kcp.NewConn2(pConn.remoteAddr, nil, 0, 0, pConn)
	if err != nil {
		pConn.Close()
		cancel()
		return fmt.Errorf("gagal init KCP: %w", err)
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 20, 0, 0)
	kcpConn.SetWindowSize(128, 128)
	kcpConn.SetMtu(pConn.mtu)

	noiseConn, err := performNoiseHandshake(kcpConn, pubKey)
	if err != nil {
		kcpConn.Close()
		pConn.Close()
		cancel()
		return fmt.Errorf("handshake Noise gagal: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 1
	smuxCfg.KeepAliveInterval = 10 * time.Second
	smuxCfg.KeepAliveTimeout = 35 * time.Second
	smuxCfg.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 65536

	session, err := smux.Client(noiseConn, smuxCfg)
	if err != nil {
		noiseConn.Close()
		cancel()
		return fmt.Errorf("gagal init smux: %w", err)
	}

	// SSH handshake lewat 1 smux stream
	sshStream, err := session.OpenStream()
	if err != nil {
		session.Close()
		cancel()
		return fmt.Errorf("gagal buka stream SSH: %w", err)
	}

	sshCfg := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPass),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = sshPass
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(sshStream, sshAddr, sshCfg)
	if err != nil {
		sshStream.Close()
		session.Close()
		cancel()
		return fmt.Errorf("handshake SSH gagal (user/pass/port?): %w", err)
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)

	ln, err := net.Listen("tcp", localSocksListen)
	if err != nil {
		sshClient.Close()
		session.Close()
		cancel()
		return fmt.Errorf("gagal bind SOCKS5 lokal: %w", err)
	}

	cancelFunc = cancel
	localLn = ln
	activeSSH = sshClient
	activeSMUX = session

	go serveLocalSocks5(ctx, ln, sshClient)

	key := &engine.Key{
		Mark:   0,
		MTU:    1500,
		Device: "fd://" + strconv.Itoa(tunFd),
		Proxy:  "socks5://" + localSocksListen,
	}

	// engine sekarang ambil alih fd
	fdOpen = false
	engine.Insert(key)
	engine.Start()

	isRunning = true
	return nil
}

func StopTunnel() {
	mu.Lock()
	defer mu.Unlock()

	if !isRunning {
		return
	}

	engine.Stop()
	if activeSSH != nil {
		_ = activeSSH.Close()
		activeSSH = nil
	}
	if activeSMUX != nil {
		_ = activeSMUX.Close()
		activeSMUX = nil
	}
	if localLn != nil {
		_ = localLn.Close()
		localLn = nil
	}
	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}
	isRunning = false
}

// --- SOCKS5 lokal (forward via SSH) ---

func serveLocalSocks5(ctx context.Context, ln net.Listener, sshClient *ssh.Client) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSocks5Client(conn, sshClient)
	}
}

func handleSocks5Client(client net.Conn, sshClient *ssh.Client) {
	defer client.Close()

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil || reqHdr[0] != 0x05 {
		return
	}
	cmd, atyp := reqHdr[1], reqHdr[3]
	addrBytes, err := readSocksAddr(client, atyp)
	if err != nil {
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(client, portBytes); err != nil {
		return
	}

	switch cmd {
	case 0x01: // CONNECT via SSH
		target := socksTargetAddr(atyp, addrBytes, portBytes)
		remote, err := sshClient.Dial("tcp", target)
		if err != nil {
			_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer remote.Close()
		if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}

		go func() {
			_, _ = io.Copy(remote, client)
			_ = remote.Close()
		}()
		_, _ = io.Copy(client, remote)

	case 0x03: // UDP ASSOCIATE (khusus DNS port 53)
		udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return
		}
		defer udpLn.Close()

		udpPort := udpLn.LocalAddr().(*net.UDPAddr).Port
		reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(udpPort >> 8), byte(udpPort)}
		if _, err := client.Write(reply); err != nil {
			return
		}

		go relayUdpDnsViaSsh(udpLn, sshClient)

		buf := make([]byte, 16)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}

	default:
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func socksTargetAddr(atyp byte, addrBytes, portBytes []byte) string {
	port := binary.BigEndian.Uint16(portBytes)
	var host string
	switch atyp {
	case 0x01:
		host = net.IP(addrBytes).String()
	case 0x03:
		host = string(addrBytes[1:])
	case 0x04:
		host = net.IP(addrBytes).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func readSocksAddr(r io.Reader, atyp byte) ([]byte, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		_, err := io.ReadFull(r, b)
		return b, err
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		b := make([]byte, 1+int(lb[0]))
		b[0] = lb[0]
		_, err := io.ReadFull(r, b[1:])
		return b, err
	case 0x04:
		b := make([]byte, 16)
		_, err := io.ReadFull(r, b)
		return b, err
	default:
		return nil, errors.New("atyp tidak didukung")
	}
}

func relayUdpDnsViaSsh(udpLn *net.UDPConn, sshClient *ssh.Client) {
	buf := make([]byte, 4096)
	for {
		n, srcAddr, err := udpLn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 10 || buf[2] != 0x00 {
			continue
		}
		atyp := buf[3]
		var headerLen int
		switch atyp {
		case 0x01:
			headerLen = 4 + 4 + 2
		case 0x03:
			if n < 5 {
				continue
			}
			headerLen = 4 + 1 + int(buf[4]) + 2
		case 0x04:
			headerLen = 4 + 16 + 2
		default:
			continue
		}
		if n <= headerLen {
			continue
		}
		dstPort := binary.BigEndian.Uint16(buf[headerLen-2 : headerLen])
		if dstPort != 53 {
			continue
		}

		socksUdpHeader := append([]byte(nil), buf[:headerLen]...)
		dnsQuery := append([]byte(nil), buf[headerLen:n]...)

		go func() {
			dnsResp, err := queryDnsOverTcpViaSsh(sshClient, dnsQuery)
			if err != nil {
				return
			}
			pkt := make([]byte, 0, len(socksUdpHeader)+len(dnsResp))
			pkt = append(pkt, socksUdpHeader...)
			pkt = append(pkt, dnsResp...)
			_, _ = udpLn.WriteToUDP(pkt, srcAddr)
		}()
	}
}

func queryDnsOverTcpViaSsh(sshClient *ssh.Client, query []byte) ([]byte, error) {
	conn, err := sshClient.Dial("tcp", dnsViaSSHAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	tcpQuery := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpQuery[:2], uint16(len(query)))
	copy(tcpQuery[2:], query)
	if _, err := conn.Write(tcpQuery); err != nil {
		return nil, err
	}

	var respLenBuf [2]byte
	if _, err := io.ReadFull(conn, respLenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(respLenBuf[:]))
	if respLen == 0 || respLen > 4096 {
		return nil, errors.New("panjang respon DNS tidak valid")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// --- Noise NK Layer ---

type noiseStreamConn struct {
	net.Conn
	sendCS  *noise.CipherState
	recvCS  *noise.CipherState
	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
}

func performNoiseHandshake(conn net.Conn, serverPubKey []byte) (net.Conn, error) {
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		Prologue:    []byte(dnsttPrologue),
		PeerStatic:  serverPubKey,
	})
	if err != nil {
		return nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeUint16Frame(conn, msg1); err != nil {
		return nil, err
	}

	msg2, err := readUint16Frame(conn)
	if err != nil {
		return nil, err
	}
	_, sendCS, recvCS, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, err
	}

	return &noiseStreamConn{Conn: conn, sendCS: sendCS, recvCS: recvCS}, nil
}

func (c *noiseStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxNoiseChunk {
			chunk = p[:maxNoiseChunk]
		}
		enc, err := c.sendCS.Encrypt(nil, nil, chunk)
		if err != nil {
			return total, err
		}
		if err := writeUint16Frame(c.Conn, enc); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *noiseStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuf) == 0 {
		enc, err := readUint16Frame(c.Conn)
		if err != nil {
			return 0, err
		}
		dec, err := c.recvCS.Decrypt(nil, nil, enc)
		if err != nil {
			return 0, err
		}
		c.readBuf = dec
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func writeUint16Frame(w io.Writer, payload []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readUint16Frame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// --- DNSTT DoH PacketConn ---

type dummyAddr string

func (a dummyAddr) Network() string { return "dnstt" }
func (a dummyAddr) String() string  { return string(a) }

type dnsttPacketConn struct {
	ctx        context.Context
	client     *http.Client
	dohURL     string
	domain     string
	clientID   [8]byte
	maxRawUp   int
	mtu        int
	remoteAddr net.Addr
	sendCh     chan []byte
	recvCh     chan []byte
	closeOnce  sync.Once
	closed     chan struct{}
}

func newDnsttPacketConn(ctx context.Context, client *http.Client, dohURL, domain string) (*dnsttPacketConn, error) {
	availChars := 253 - len(domain) - 1
	numLabels := (availChars + 63) / 64
	usableBase32Chars := availChars - numLabels
	maxRaw := (usableBase32Chars * 5) / 8
	if maxRaw < 32 {
		return nil, errors.New("domain tunnel terlalu panjang untuk DNS encoding")
	}

	var cid [8]byte
	if _, err := rand.Read(cid[:]); err != nil {
		return nil, err
	}

	mtu := maxRaw - 8 - 1
	if mtu > 1200 {
		mtu = 1200
	}

	c := &dnsttPacketConn{
		ctx: ctx, client: client, dohURL: dohURL, domain: domain,
		clientID: cid, maxRawUp: maxRaw, mtu: mtu,
		remoteAddr: dummyAddr(domain),
		sendCh:     make(chan []byte, 256),
		recvCh:     make(chan []byte, 256),
		closed:     make(chan struct{}),
	}
	for i := 0; i < 4; i++ {
		go c.pollWorker()
	}
	return c, nil
}

func (c *dnsttPacketConn) pollWorker() {
	delay := 100 * time.Millisecond
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.closed:
			return
		default:
		}

		var firstPkt []byte
		select {
		case firstPkt = <-c.sendCh:
			delay = 0
		case <-time.After(delay):
			if delay < 1500*time.Millisecond {
				delay += 200 * time.Millisecond
			}
		case <-c.ctx.Done():
			return
		case <-c.closed:
			return
		}

		var raw bytes.Buffer
		raw.Write(c.clientID[:])

		if firstPkt != nil {
			raw.WriteByte(byte(len(firstPkt)))
			raw.Write(firstPkt)
			for raw.Len()+1 < c.maxRawUp {
				select {
				case nextPkt := <-c.sendCh:
					if raw.Len()+1+len(nextPkt) <= c.maxRawUp {
						raw.WriteByte(byte(len(nextPkt)))
						raw.Write(nextPkt)
					} else {
						select {
						case c.sendCh <- nextPkt:
						default:
						}
						goto sendDNS
					}
				default:
					goto sendDNS
				}
			}
		} else {
			raw.WriteByte(0x00)
			var pad [8]byte
			_, _ = rand.Read(pad[:])
			raw.Write(pad[:])
		}

	sendDNS:
		gotData := c.exchangeDoH(raw.Bytes())
		if gotData {
			delay = 0
		}
	}
}

func (c *dnsttPacketConn) exchangeDoH(rawPayload []byte) bool {
	encoded := strings.ToLower(b32Encoding.EncodeToString(rawPayload))
	var qnameBuilder strings.Builder
	for i := 0; i < len(encoded); i += 63 {
		end := i + 63
		if end > len(encoded) {
			end = len(encoded)
		}
		qnameBuilder.WriteString(encoded[i:end])
		qnameBuilder.WriteByte('.')
	}
	qnameBuilder.WriteString(c.domain)
	qnameBuilder.WriteByte('.')

	name, err := dnsmessage.NewName(qnameBuilder.String())
	if err != nil {
		return false
	}

	var idBuf [2]byte
	_, _ = rand.Read(idBuf[:])
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(idBuf[:]),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		}},
	}

	wireQuery, err := msg.Pack()
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.dohURL, bytes.NewReader(wireQuery))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return false
	}

	var dnsResp dnsmessage.Message
	if err := dnsResp.Unpack(body); err != nil {
		return false
	}

	var downstream []byte
	for _, ans := range dnsResp.Answers {
		if ans.Header.Type == dnsmessage.TypeTXT {
			if txt, ok := ans.Body.(*dnsmessage.TXTResource); ok {
				for _, s := range txt.TXT {
					downstream = append(downstream, []byte(s)...)
				}
			}
		}
	}

	receivedAny := false
	for len(downstream) >= 2 {
		pktLen := int(binary.BigEndian.Uint16(downstream[:2]))
		downstream = downstream[2:]
		if pktLen == 0 || pktLen > len(downstream) {
			break
		}
		pkt := append([]byte(nil), downstream[:pktLen]...)
		downstream = downstream[pktLen:]
		select {
		case c.recvCh <- pkt:
			receivedAny = true
		case <-c.closed:
			return receivedAny
		}
	}
	return receivedAny
}

func (c *dnsttPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 255 || len(p) > c.maxRawUp-9 {
		return 0, errors.New("paket KCP melebihi kapasitas QNAME")
	}
	cp := append([]byte(nil), p...)
	select {
	case c.sendCh <- cp:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *dnsttPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.recvCh:
		n := copy(p, pkt)
		return n, c.remoteAddr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *dnsttPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *dnsttPacketConn) LocalAddr() net.Addr                { return dummyAddr("127.0.0.1:0") }
func (c *dnsttPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *dnsttPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dnsttPacketConn) SetWriteDeadline(t time.Time) error { return nil }