package tlsrotater

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// TLSRotater rotates when necessary
type TLSRotater struct {
	*keypairReloader
	CA         []byte
	client     *vaultapi.Client
	commonName string
	reloadChan chan int
	ticker     *time.Ticker
}

func (rotater *TLSRotater) loadCertsFromVault() error {
	params := make(map[string]interface{})
	params["common_name"] = rotater.commonName
	params["alt_names"] = "localhost"
	params["ttl"] = "1h"
	secret, err := rotater.client.Logical().Write("pki/issue/"+rotater.commonName, params)
	if err != nil {
		return err
	}
	issuingCaContents := secret.Data["issuing_ca"].(string)
	rotater.CA = []byte(issuingCaContents)
	certificateContents := secret.Data["certificate"].(string)
	ioutil.WriteFile("cert.pem", []byte(certificateContents), 0)
	privateKeyContents := secret.Data["private_key"].(string)
	ioutil.WriteFile("key.pem", []byte(privateKeyContents), 0)
	bundle := string(certificateContents) + string(issuingCaContents)
	ioutil.WriteFile("bundle.pem", []byte(bundle), 0)
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(issuingCaContents)) {
		return fmt.Errorf("Invalid CA")
	}
	return nil
}

func (rotater *TLSRotater) Start() {
	err := rotater.loadCertsFromVault()
	if err != nil {
		panic(err)
	}
	multiplier := 0.7 + 0.2*rand.Float64()
	ticker := time.NewTicker(time.Duration(int64(multiplier * float64(time.Minute.Nanoseconds()))))
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := rotater.loadCertsFromVault(); err != nil {
					panic(fmt.Errorf("Error while loading certs: %#v", err))
				}
				rotater.reloadChan <- 1
			}
		}
	}()
}

func (rotater *TLSRotater) Stop() {
	if rotater.ticker != nil {
		rotater.ticker.Stop()
	}
}

// NewTLSRotater creates a new TLS rotater
func NewTLSRotater(client *vaultapi.Client, commonName string) (*TLSRotater, error) {
	result := &TLSRotater{
		commonName: commonName,
		client:     client,
	}
	err := result.loadCertsFromVault()
	if err != nil {
		panic(err)
	}
	reloader, c, err := newKeypairReloader("bundle.pem", "key.pem")
	if err != nil {
		return nil, err
	}
	result.keypairReloader = reloader
	result.reloadChan = c

	return result, err
}
