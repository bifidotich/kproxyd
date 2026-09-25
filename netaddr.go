package main

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Адреса интерфейсов роутера. Кэшируются на 10 секунд: спрашивать ядро на каждое соединение
// незачем, а меняются они редко (переподключение PPPoE, новый префикс DHCPv6-PD).
var routerAddrs struct {
	mu  sync.Mutex
	at  time.Time
	own []netip.Addr   // все адреса роутера
	lan []netip.Prefix // сети домашних мостов (br0, br1…) — в том числе глобальные IPv6
}

func routerNets() (own []netip.Addr, lan []netip.Prefix) {
	r := &routerAddrs
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.at) < 10*time.Second {
		return r.own, r.lan
	}
	own, lan = []netip.Addr{}, []netip.Prefix{}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			own = append(own, ip)
			if strings.HasPrefix(ifc.Name, "br") {
				ones, _ := ipn.Mask.Size()
				lan = append(lan, netip.PrefixFrom(ip, ones).Masked())
			}
		}
	}
	r.own, r.lan, r.at = own, lan, time.Now()
	return own, lan
}

// isLocalAddr — клиент из локальной сети: loopback, частные диапазоны, link-local, а также
// глобальные IPv6-адреса из префикса домашней сети (их раздаёт роутер по DHCPv6-PD/SLAAC).
// netip понимает зону IPv6 (fe80::1%br0), которую RemoteAddr отдаёт для link-local клиентов.
func isLocalAddr(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	if ip.Is6() {
		_, lan := routerNets()
		for _, p := range lan {
			if p.Contains(ip.WithZone("")) {
				return true
			}
		}
	}
	return false
}

var errDstForbidden = errors.New("адрес назначения — сам роутер")

// dstAllowed — можно ли вести SOCKS5-соединение на этот адрес. Сам роутер закрыт: иначе клиент
// прокси добрался бы до служб, доступных только изнутри, например RCI на 127.0.0.1:79 без пароля.
func dstAllowed(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	own, _ := routerNets()
	for _, a := range own {
		if a == ip {
			return false
		}
	}
	return true
}

// guardDst проверяет адрес уже после разрешения имени — перед самим подключением,
// так что не помогает и домен, указывающий на 127.0.0.1.
func guardDst(d *net.Dialer) {
	prev := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		if ap, err := netip.ParseAddrPort(address); err == nil && !dstAllowed(ap.Addr()) {
			return errDstForbidden
		}
		if prev != nil {
			return prev(network, address, c)
		}
		return nil
	}
}
