module dnstt-vpn-core

go 1.22

require (
	github.com/flynn/noise v1.1.0
	github.com/xjasonlyu/tun2socks/v2 v2.5.2
	github.com/xtaci/kcp-go/v5 v5.6.13
	github.com/xtaci/smux v1.5.24
	golang.org/x/mobile v0.0.0-20251209145715-2553ed8ce294
	golang.org/x/net v0.29.0
)

replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20260906120324-45bde0d1defa