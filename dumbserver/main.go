package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirlatrom/tls-sidecar-playground/tlsrotater"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q\n", html.EscapeString(r.URL.Path))
		for _, cert := range r.TLS.PeerCertificates {
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
			fmt.Fprintf(w, "I see you are: %q with serial %q\n", cert.Subject.CommonName, prettySerial)
		}
		r.Close = true
	})

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

	rotater := tlsrotater.NewTLSRotater(client, "dumbserver", []string{"localhost"})
	if err := rotater.Start(); err != nil {
		panic(err)
	}
	defer rotater.Stop()
	log.Println("Created keypair reloader")

	tlsConfig := tls.Config{
		RootCAs:    rotater.CACertPool,
		ClientCAs:  rotater.CACertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.GetCertificate = rotater.GetCertificateFunc()
	srv := http.Server{
		Addr:      ":443",
		TLSConfig: &tlsConfig,
	}
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
	log.Println("Done serving")
}
