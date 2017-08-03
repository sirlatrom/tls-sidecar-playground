package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirlatrom/tlsrotater"
)

var (
	targetScheme string
	targetHost   string
)

func main() {
	if v, ok := os.LookupEnv("targetScheme"); ok {
		targetScheme = v
	} else {
		panic("Must supply targetScheme")
	}
	if v, ok := os.LookupEnv("targetHost"); ok {
		targetHost = v
	} else {
		panic("Must supply targetHost")
	}
	theURL := &url.URL{
		Scheme: targetScheme,
		Host:   targetHost,
	}
	servePort := "8080"
	if overridePort, ok := os.LookupEnv("LISTEN_PORT"); ok {
		servePort = overridePort
	}

	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		panic(err)
	}
	log.Println("Created Vault client")
	if _, ok := os.LookupEnv("VAULT_TOKEN"); !ok {
		contents, err := ioutil.ReadFile("/run/secrets/vault_token")
		if err != nil {
			panic(err)
		}
		client.SetToken(string(contents))
	}
	log.Println("Read vault token")

	rotater, err := tlsrotater.NewTLSRotater(client, "outproxy")
	if err != nil {
		panic(err)
	}
	rotater.Start()
	defer rotater.Stop()

	log.Println("Created keypair reloader")
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(rotater.CA) {
		panic("Invalid CA")
	}
	log.Println("Loaded CA")
	tlsConfig := tls.Config{
		RootCAs: certPool,
		GetClientCertificate: func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// for _, ca := range requestInfo.AcceptableCAs {
			// 	if bytes.Equal(ca, rotater.CA) {
			return rotater.GetCertificateFunc()(nil)
			// 	}
			// 	fmt.Printf("Unknown CA:\n%v\n", string(ca))
			// }
			// return nil, fmt.Errorf("Cannot find our root CA in server's accepted list")
		},
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(theURL)
	reverseProxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tlsConfig,
	}
	http.HandleFunc("/", handler(reverseProxy))
	err = http.ListenAndServe(":"+servePort, nil)
	if err != nil {
		panic(err)
	}
	log.Println("Done serving")
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Host = targetHost
		p.ServeHTTP(w, r)
	}
}
