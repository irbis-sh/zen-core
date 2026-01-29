package asset

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type certGenerator interface {
	GetCertificate(host string) (*tls.Certificate, error)
}

// Resolver returns asset content based on path and referer.
type Resolver interface {
	Resolve(path, hostname string) (contentType string, body []byte, err error)
}

// Server hosts asset resources over HTTPS.
type Server struct {
	addr          string
	resolver      Resolver
	certGenerator certGenerator
	httpServer    *http.Server
}

// NewServer creates a new HTTPS asset server bound to [host].
func NewServer(port int, resolver Resolver, certGenerator certGenerator) (*Server, error) {
	if port == 0 {
		return nil, errors.New("port cannot be 0")
	}
	if resolver == nil {
		return nil, errors.New("resolver is nil")
	}
	if certGenerator == nil {
		return nil, errors.New("certGenerator is nil")
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	s := &Server{
		addr:          addr,
		resolver:      resolver,
		certGenerator: certGenerator,
	}

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s, nil
}

// ListenAndServe starts the HTTPS server and blocks.
func (s *Server) ListenAndServe() error {
	tlsConfig := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.certGenerator.GetCertificate(host)
		},
		MinVersion: tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", s.addr, tlsConfig)
	if err != nil {
		return err
	}

	log.Printf("assetserver: listening on address %s", s.addr)

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("assetserver: error serving: %v", err)
		}
	}()

	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var refererURL *url.URL
	raw := r.Referer()
	if raw == "" {
		http.Error(w, "missing referer", http.StatusBadRequest)
		return
	}
	if parsed, err := url.Parse(raw); err != nil {
		log.Printf("assetserver: invalid referer URL %q: %v", raw, err)
		http.Error(w, "invalid referer", http.StatusBadRequest)
		return
	} else {
		refererURL = parsed
	}

	contentType, body, err := s.resolver.Resolve(r.URL.Path, refererURL.Hostname())
	if err != nil {
		log.Printf("assetserver: failed to resolve asset %q: %v", r.URL.Path, err)
		http.Error(w, "asset resolution error", http.StatusInternalServerError)
		return
	}
	if len(body) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
