package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Сколько ждать первых байтов от клиента. Браузер шлёт ClientHello сразу после ответа SOCKS5;
// ожидание затягивается только у протоколов, где первым говорит сервер, а их на портах 443 и 80 нет.
const sniffWait = 800 * time.Millisecond

// sniffPrefix читает начало данных клиента, чтобы узнать домен: запись TLS с ClientHello целиком
// (ровно её — следующие байты, например ранние данные TLS 1.3, остаются в сокете и уйдут только
// выбранному серверу) или начало HTTP-запроса. Прочитанное нужно отправить серверу первым.
func sniffPrefix(c net.Conn) (prefix []byte, host string, isTLS bool) {
	_ = c.SetReadDeadline(time.Now().Add(sniffWait))
	defer c.SetReadDeadline(time.Time{})
	var hdr [5]byte
	n, err := io.ReadFull(c, hdr[:])
	if err != nil {
		return append([]byte(nil), hdr[:n]...), "", false
	}
	if hdr[0] == 0x16 && hdr[1] == 3 {
		l := int(binary.BigEndian.Uint16(hdr[3:5]))
		if l == 0 || l > 16<<10 {
			return hdr[:], "", false
		}
		buf := make([]byte, 5+l)
		copy(buf, hdr[:])
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := io.ReadFull(c, buf[5:])
		if err != nil {
			return buf[:5+m], "", false
		}
		return buf, clientHelloSNI(buf[5:]), true
	}
	// похоже на HTTP: дочитываем, что уже пришло, в пределах 4 КБ — заголовок Host обычно в начале
	buf := make([]byte, 4096)
	copy(buf, hdr[:])
	n = 5
	for n < len(buf) && !bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	return buf[:n], httpHost(buf[:n]), false
}

// clientHelloSNI достаёт имя сервера (SNI) из тела записи TLS с ClientHello.
// С ECH это внешнее имя (например, cloudflare-ech.com), а настоящий домен скрыт.
func clientHelloSNI(b []byte) string {
	if len(b) < 4 || b[0] != 1 { // тип сообщения: ClientHello
		return ""
	}
	b = b[4:]
	skip := func(n int) bool {
		if len(b) < n {
			return false
		}
		b = b[n:]
		return true
	}
	vec := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[i])
		}
		return skip(lenBytes + n)
	}
	// версия, random, session_id, cipher_suites, compression_methods
	if !skip(2+32) || !vec(1) || !vec(2) || !vec(1) || len(b) < 2 {
		return ""
	}
	ext := b[2:]
	if n := int(binary.BigEndian.Uint16(b)); n < len(ext) {
		ext = ext[:n]
	}
	for len(ext) >= 4 {
		typ, n := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+n {
			return ""
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		if typ != 0 { // server_name
			continue
		}
		if len(data) < 2 {
			return ""
		}
		data = data[2:]
		for len(data) >= 3 {
			nt, l := data[0], int(binary.BigEndian.Uint16(data[1:]))
			if len(data) < 3+l {
				return ""
			}
			if nt == 0 {
				if h := normDomain(string(data[3 : 3+l])); validHost(h) {
					return h
				}
				return ""
			}
			data = data[3+l:]
		}
		return ""
	}
	return ""
}

// httpHost — домен из заголовка Host начала HTTP-запроса.
func httpHost(b []byte) string {
	for _, line := range strings.Split(string(b), "\r\n")[1:] {
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "host") {
			continue
		}
		v = strings.TrimSpace(v)
		if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
		if h := normDomain(v); validHost(h) {
			return h
		}
		return ""
	}
	return ""
}

// Зоны второго уровня, в которых регистрируют домены: example.co.uk, example.com.ru.
var secondLevel = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "gov": true, "edu": true,
	"ac": true, "or": true, "ne": true, "go": true, "msk": true, "spb": true,
}

// siteOf — «сайт» для кэша и мониторинга: домен второго уровня (www.youtube.com и
// rr1---sn-x.googlevideo.com дают youtube.com и googlevideo.com). Блокируют обычно весь сайт,
// так что знание об одном его адресе сразу пригодится для остальных.
func siteOf(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	k := 2
	if len(labels[n-1]) == 2 && secondLevel[labels[n-2]] {
		k = 3
	}
	return strings.Join(labels[n-k:], ".")
}

// hostMatch — домен правила совпадает с именем или является его родителем.
func hostMatch(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}
