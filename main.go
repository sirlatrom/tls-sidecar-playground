package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirlatrom/tlsrotater"
)

var (
	targetScheme string
	targetHost   string
	contextRoot  string
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
	if v, ok := os.LookupEnv("contextRoot"); ok {
		contextRoot = v
	} else {
		contextRoot = ""
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

	rotater := tlsrotater.NewTLSRotater(client, "outproxy", []string{"localhost"})
	if err := rotater.Start(); err != nil {
		panic(err)
	}
	defer rotater.Stop()
	log.Println("Created keypair reloader")

	tlsConfig := tls.Config{
		RootCAs:              rotater.CACertPool,
		ClientCAs:            rotater.CACertPool,
		GetClientCertificate: rotater.GetClientCertificateFunc(),
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(theURL)
	reverseProxy.ModifyResponse = func(response *http.Response) error {
		for _, cert := range response.TLS.PeerCertificates {
			var prettySerial string
			serial := hex.EncodeToString(cert.SerialNumber.Bytes())
			for i := range serial {
				if i%2 == 0 && i > 0 {
					if i > 2 {
						prettySerial += ":"
					}
					prettySerial += serial[i-2 : i]
				}
			}
			fmt.Printf("Server subject: %q, serial: %q\n", cert.Subject.CommonName, prettySerial)
		}
		return nil
	}
	reverseProxy.Transport = &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
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
		r.URL.Host = targetHost
		r.URL.Path = strings.TrimPrefix(r.URL.Path, contextRoot)
		p.ServeHTTP(w, r)
	}
}
