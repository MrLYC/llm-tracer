package collector

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/liuyicong/llm-tracer/internal/parser"
)

// LoopbackTap is an ephemeral local HTTP + HTTPS MITM proxy used as fallback for static-pie (codex/rustls)
// and Go (crypto/tls) binaries that bypass libc LD_PRELOAD and ptrace.
type LoopbackTap struct {
	ln       net.Listener
	addr     string
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caPath   string
	certMu   sync.Mutex
	certMap  map[string]*tls.Certificate
	seq      atomic.Uint64
	onChunk  func(connID string, dir parser.Direction, data []byte)
}

func NewLoopbackTap(hooksDir string, onChunk func(connID string, dir parser.Direction, data []byte)) (*LoopbackTap, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "LLM-Tracer Ephemeral Local CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	// Append system CA bundle if present so upstream verification inside target process still trusts public CAs
	var combinedPEM bytes.Buffer
	for _, sysCAPath := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		if sysCA, err := os.ReadFile(sysCAPath); err == nil && len(sysCA) > 0 {
			combinedPEM.Write(sysCA)
			combinedPEM.WriteByte('\n')
			break
		}
	}
	combinedPEM.Write(caPEM)
	caPath := filepath.Join(hooksDir, "llm_tracer_ca_bundle.pem")
	if err := os.WriteFile(caPath, combinedPEM.Bytes(), 0o644); err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tap := &LoopbackTap{
		ln:      ln,
		addr:    ln.Addr().String(),
		caCert:  caCert,
		caKey:   caKey,
		caPath:  caPath,
		certMap: make(map[string]*tls.Certificate),
		onChunk: onChunk,
	}
	go tap.serve()
	return tap, nil
}

func (t *LoopbackTap) ProxyURL() string {
	return "http://" + t.addr
}

func (t *LoopbackTap) CABundlePath() string {
	return t.caPath
}

func (t *LoopbackTap) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

func (t *LoopbackTap) serve() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		go t.handleConn(conn)
	}
}

func (t *LoopbackTap) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		t.handleConnect(clientConn, req.Host)
		return
	}
	t.forwardPlainHTTP(clientConn, req)
}

func (t *LoopbackTap) forwardPlainHTTP(clientConn net.Conn, req *http.Request) {
	connID := fmt.Sprintf("tap_%d", t.seq.Add(1))
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	reqBytes, _ := dumpHTTPRequestWire(req)
	if len(reqBytes) > 0 && t.onChunk != nil {
		t.onChunk(connID, parser.DirWrite, reqBytes)
	}

	tr := &http.Transport{DisableCompression: false}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var respHead bytes.Buffer
	fmt.Fprintf(&respHead, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(&respHead, "%s: %s\r\n", k, v)
		}
	}
	respHead.WriteString("\r\n")
	_, _ = clientConn.Write(respHead.Bytes())

	var respBodyBuf bytes.Buffer
	buf := make([]byte, 16384)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			_, _ = clientConn.Write(buf[:n])
			respBodyBuf.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	if t.onChunk != nil {
		var wireResp bytes.Buffer
		fmt.Fprintf(&wireResp, "HTTP/1.1 %s\r\n", resp.Status)
		for k, vv := range resp.Header {
			if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vv {
				fmt.Fprintf(&wireResp, "%s: %s\r\n", k, v)
			}
		}
		fmt.Fprintf(&wireResp, "Content-Length: %d\r\n\r\n", respBodyBuf.Len())
		wireResp.Write(respBodyBuf.Bytes())
		t.onChunk(connID, parser.DirRead, wireResp.Bytes())
	}
}

func (t *LoopbackTap) handleConnect(clientConn net.Conn, targetHost string) {
	if !strings.Contains(targetHost, ":") {
		targetHost += ":443"
	}
	hostOnly := strings.Split(targetHost, ":")[0]
	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	leafCert, err := t.getOrCreateLeafCert(hostOnly)
	if err != nil {
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		return
	}
	defer tlsClient.Close()

	upConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", targetHost, &tls.Config{
		ServerName:         hostOnly,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		return
	}
	defer upConn.Close()

	connID := fmt.Sprintf("taptls_%d", t.seq.Add(1))
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := tlsClient.Read(buf)
			if n > 0 {
				if t.onChunk != nil {
					cp := make([]byte, n)
					copy(cp, buf[:n])
					t.onChunk(connID, parser.DirWrite, cp)
				}
				_, _ = upConn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := upConn.Read(buf)
			if n > 0 {
				if t.onChunk != nil {
					cp := make([]byte, n)
					copy(cp, buf[:n])
					t.onChunk(connID, parser.DirRead, cp)
				}
				_, _ = tlsClient.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}

func (t *LoopbackTap) getOrCreateLeafCert(host string) (*tls.Certificate, error) {
	t.certMu.Lock()
	defer t.certMu.Unlock()
	if c, ok := t.certMap[host]; ok {
		return c, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, t.caCert, &priv.PublicKey, t.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, t.caCert.Raw},
		PrivateKey:  priv,
	}
	t.certMap[host] = cert
	return cert, nil
}

func dumpHTTPRequestWire(req *http.Request) ([]byte, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	var b bytes.Buffer
	pathAndQuery := req.URL.RequestURI()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, pathAndQuery)
	fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	for k, vv := range req.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(bodyBytes))
	b.Write(bodyBytes)
	return b.Bytes(), nil
}
