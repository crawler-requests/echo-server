// Command loadtest drives the echo server at high concurrency.
//
// It exists so the throughput claims in the README can be reproduced instead of
// taken on faith. Two modes:
//
//	hold  — open N connections and keep them idle (measures memory per
//	        connection and how many sockets the host really supports)
//	drive — open N connections and hammer them with keep-alive requests
//	        (measures sustained throughput and latency)
//
// It speaks HTTP/1.1 by hand (or TLS) rather than via net/http, because the
// client itself must not become the bottleneck before the server does.
//
// Usage:
//
//	go run ./tools/loadtest -mode hold  -c 100000 -addr 127.0.0.1:8080 -la 127.0.0.1,127.0.0.2
//	go run ./tools/loadtest -mode drive -c 100000 -addr 127.0.0.1:8080 -path /ip -la ...
//
// -la spreads connections across local source IPs. Without it a single host
// caps out at roughly 64k *outgoing* connections (one port range per source
// address), which looks like a server failure but is a client limit.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	mode := flag.String("mode", "drive", "hold (keep sockets open) or drive (keep sending requests)")
	conns := flag.Int("c", 1000, "number of concurrent connections")
	addr := flag.String("addr", "127.0.0.1:8080", "host:port of the server")
	path := flag.String("path", "/ip", "request path")
	tlsOn := flag.Bool("tls", false, "use TLS")
	insecure := flag.Bool("k", true, "skip certificate verification (self-signed)")
	dur := flag.Duration("d", 10*time.Second, "test duration")
	la := flag.String("la", "", "comma-separated local source IPs to spread connections across")
	ua := flag.String("ua", "loadtest/1.0", "User-Agent header")
	flag.Parse()

	src := localIPs(*la)

	var (
		dialed    atomic.Int64
		failed    atomic.Int64
		reqs      atomic.Int64
		errs      atomic.Int64
		mu        sync.Mutex
		lats      []float64
		connsHeld []net.Conn
	)
	deadline := time.Now().Add(*dur)
	start := time.Now()

	dial := func(n int64) (net.Conn, error) {
		d := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
		if len(src) > 0 {
			d.LocalAddr = &net.TCPAddr{IP: src[n%int64(len(src))]}
		}
		if *tlsOn {
			return tls.DialWithDialer(d, "tcp", *addr, &tls.Config{InsecureSkipVerify: *insecure})
		}
		return d.Dial("tcp", *addr)
	}

	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := dial(int64(idx))
			if err != nil {
				failed.Add(1)
				return
			}
			defer c.Close()
			dialed.Add(1)

			if *mode == "hold" {
				mu.Lock()
				connsHeld = append(connsHeld, c)
				mu.Unlock()
				time.Sleep(time.Until(deadline))
				return
			}

			br := bufio.NewReaderSize(c, 4096)
			host := *addr
			for time.Now().Before(deadline) {
				t0 := time.Now()
				req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n\r\n", *path, host, *ua)
				if _, err := c.Write([]byte(req)); err != nil {
					errs.Add(1)
					return
				}
				// Read status line, headers, and exactly Content-Length bytes.
				// Reading a fixed number of lines would stall waiting for the
				// *next* response, which is the classic load-generator bug.
				if _, err := br.ReadString('\n'); err != nil {
					errs.Add(1)
					return
				}
				clen := 0
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						errs.Add(1)
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
					lower := strings.ToLower(line)
					if strings.HasPrefix(lower, "content-length:") {
						clen = atoiTrim(line[15:])
					}
				}
				if clen > 0 {
					if _, err := io.ReadFull(br, make([]byte, clen)); err != nil {
						errs.Add(1)
						return
					}
				}
				ms := float64(time.Since(t0).Microseconds()) / 1000
				reqs.Add(1)
				mu.Lock()
				lats = append(lats, ms)
				mu.Unlock()
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				fmt.Fprintf(os.Stderr, "\rdialed=%d reqs=%d errs=%d failed=%d", dialed.Load(), reqs.Load(), errs.Load(), failed.Load())
			case <-done:
				return
			}
		}
	}()
	wg.Wait()
	close(done)
	fmt.Fprintf(os.Stderr, "\n")

	el := time.Since(start).Seconds()
	fmt.Printf("mode=%s conns=%d dialed=%d failed=%d reqs=%d errs=%d rps=%.0f\n",
		*mode, *conns, dialed.Load(), failed.Load(), reqs.Load(), errs.Load(), float64(reqs.Load())/el)
	if len(lats) > 0 {
		sort.Float64s(lats)
		at := func(p float64) float64 {
			i := int(float64(len(lats)) * p)
			if i >= len(lats) {
				i = len(lats) - 1
			}
			return lats[i]
		}
		fmt.Printf("latency ms: p50=%.2f p90=%.2f p99=%.2f p999=%.2f max=%.2f\n",
			at(.5), at(.9), at(.99), at(.999), lats[len(lats)-1])
	}
}

// localIPs parses the -la list.
func localIPs(spec string) []net.IP {
	out := []net.IP{}
	for _, part := range strings.Split(spec, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// atoiTrim parses a decimal integer, ignoring a trailing CR.
func atoiTrim(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else if n > 0 {
			break
		}
	}
	return n
}
