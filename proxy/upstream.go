package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
)

// ExternalProxyConfig holds the configuration for an external upstream proxy.
type ExternalProxyConfig struct {
	// Protocol is the proxy protocol: "http" or "socks5".
	Protocol string
	// Host is the proxy hostname or IP address.
	Host string
	// Port is the proxy port.
	Port int
	// Username is the optional authentication username.
	Username string
	// Password is the optional authentication password.
	Password string
}

// Address returns the host:port string of the proxy.
func (c ExternalProxyConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// ProxyOption configures the Proxy.
type ProxyOption func(*Proxy)

// WithExternalProxy returns a ProxyOption that routes all outbound
// connections through the specified external proxy.
func WithExternalProxy(cfg ExternalProxyConfig) ProxyOption {
	return func(p *Proxy) {
		switch cfg.Protocol {
		case "socks5":
			var auth *proxy.Auth
			if cfg.Username != "" {
				auth = &proxy.Auth{
					User:     cfg.Username,
					Password: cfg.Password,
				}
			}
			dialer, err := proxy.SOCKS5("tcp", cfg.Address(), auth, proxy.Direct)
			if err != nil {
				log.Printf("failed to create SOCKS5 dialer for %s: %v, falling back to direct connection", cfg.Address(), err)
				return
			}
			p.dialer = dialer
		case "http":
			p.dialer = &httpConnectDialer{
				proxyAddr: cfg.Address(),
				username:  cfg.Username,
				password:  cfg.Password,
			}
		default:
			log.Printf("unsupported external proxy protocol %q, falling back to direct connection", cfg.Protocol)
		}
	}
}

// httpConnectDialer implements proxy.Dialer for HTTP CONNECT proxies.
type httpConnectDialer struct {
	proxyAddr string
	username  string
	password  string
}

// Dial connects to the address through the HTTP CONNECT proxy.
func (d *httpConnectDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP proxy %s: %w", d.proxyAddr, err)
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		Host:   addr,
		URL:    &url.URL{Host: addr},
		Header: make(http.Header),
	}

	if d.username != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(d.username + ":" + d.password))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT to %s via proxy %s failed: %s", addr, d.proxyAddr, resp.Status)
	}

	return conn, nil
}
