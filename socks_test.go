package main

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// recConn — назначение для relay: запоминает каждую запись отдельно.
type recConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (r *recConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.writes = append(r.writes, append([]byte(nil), b...))
	r.mu.Unlock()
	return len(b), nil
}

func (r *recConn) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.writes...)
}

func (r *recConn) data() []byte { return bytes.Join(r.snapshot(), nil) }

// tcpPair — два конца настоящего TCP-соединения через loopback: в отличие от net.Pipe,
// ядро буферизует данные, как на роутере.
func tcpPair(t *testing.T) (src, w net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acc <- c
	}()
	w, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	src = <-acc
	if src == nil {
		t.Fatal("accept не удался")
	}
	t.Cleanup(func() { src.Close(); w.Close() })
	return src, w
}

type relayRes struct {
	n   int64
	err error
}

func startRelay(src net.Conn, coalesce bool) (*recConn, chan relayRes) {
	dst := &recConn{}
	ch := make(chan relayRes, 1)
	go func() {
		n, err := relay(dst, src, make([]byte, 16<<10), coalesce)
		ch <- relayRes{n, err}
	}()
	return dst, ch
}

func waitRelay(t *testing.T, ch chan relayRes) relayRes {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("relay не завершился")
		return relayRes{}
	}
}

// waitFor ждёт, пока в dst наберётся n байт.
func waitFor(t *testing.T, dst *recConn, n int) {
	t.Helper()
	for start := time.Now(); len(dst.data()) < n; {
		if time.Since(start) > 2*time.Second {
			t.Fatalf("за 2 с дошло %d байт из %d", len(dst.data()), n)
		}
		time.Sleep(100 * time.Microsecond)
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// Данные доходят без потерь и в том же порядке при любых размерах порций, EOF — не ошибка.
func TestRelayIntegrity(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		src, w := tcpPair(t)
		dst, ch := startRelay(src, coalesce)
		want := pattern(300 << 10)
		for off, i := 0, 0; off < len(want); i++ {
			sz := []int{1, 200, 1400, 5000, 17 << 10, 300}[i%6]
			if off+sz > len(want) {
				sz = len(want) - off
			}
			if _, err := w.Write(want[off : off+sz]); err != nil {
				t.Fatal(err)
			}
			off += sz
			if i%50 == 0 {
				time.Sleep(3 * time.Millisecond) // паузы длиннее окна склейки
			}
		}
		w.Close()
		r := waitRelay(t, ch)
		if r.err != nil {
			t.Fatalf("coalesce=%v: ошибка %v", coalesce, r.err)
		}
		if r.n != int64(len(want)) || !bytes.Equal(dst.data(), want) {
			t.Fatalf("coalesce=%v: данные искажены: %d из %d байт", coalesce, r.n, len(want))
		}
	}
}

// В начале потока мелкие порции уходят сразу по одной; после coalesceAfter частые мелкие
// порции уходят заметно меньшим числом записей.
func TestRelayCoalesces(t *testing.T) {
	const small, count = 200, 200
	src, w := tcpPair(t)
	dst, ch := startRelay(src, true)

	sent := 0
	for i := 0; i < 20; i++ {
		_, _ = w.Write(pattern(small))
		sent += small
		waitFor(t, dst, sent) // следующая порция — только после пересылки предыдущей
	}
	for i, got := range dst.snapshot() {
		if len(got) != small {
			t.Fatalf("начало потока: запись %d — %d байт, ждали %d", i, len(got), small)
		}
	}
	_, _ = w.Write(pattern(coalesceAfter))
	sent += coalesceAfter
	waitFor(t, dst, sent)
	before := len(dst.snapshot())

	for i := 0; i < count; i++ {
		_, _ = w.Write(pattern(small))
		if i%20 == 19 {
			time.Sleep(200 * time.Microsecond)
		}
	}
	w.Close()
	if r := waitRelay(t, ch); r.err != nil {
		t.Fatal(r.err)
	}
	if tail := len(dst.snapshot()) - before; tail > count/4 {
		t.Fatalf("мелкие порции почти не склеились: %d записей на %d порций", tail, count)
	}
}

// Мелкая порция в большом потоке не задерживается надолго, даже если следом ничего не придёт.
func TestRelayCoalesceBounded(t *testing.T) {
	src, w := tcpPair(t)
	dst, _ := startRelay(src, true)
	_, _ = w.Write(pattern(coalesceAfter))
	waitFor(t, dst, coalesceAfter)
	start := time.Now()
	_, _ = w.Write([]byte("tail"))
	waitFor(t, dst, coalesceAfter+4)
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("мелкая порция задержана на %v", d)
	}
	if !bytes.HasSuffix(dst.data(), []byte("tail")) {
		t.Fatal("хвост потока искажён")
	}
}

// Если соединение закрыли, пока relay ждал склейки, relay возвращает ошибку, а не успех.
func TestRelayClosedDuringCoalesce(t *testing.T) {
	src, w := tcpPair(t)
	dst, ch := startRelay(src, true)
	_, _ = w.Write(pattern(coalesceAfter))
	waitFor(t, dst, coalesceAfter)
	_, _ = w.Write([]byte("x"))
	time.Sleep(200 * time.Microsecond) // relay прочитал «x» и ждёт склейки
	src.Close()
	if r := waitRelay(t, ch); r.err == nil {
		t.Fatal("ошибка чтения потерялась")
	}
}
