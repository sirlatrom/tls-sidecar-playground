/*
Copyright (C) 2017 Sune Keller <absukl@almbrand.dk> 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
package tlsrotater

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// TLSRotater rotates when necessary
type TLSRotater struct {
	CACertPool *x509.CertPool

	client     *vaultapi.Client
	commonName string

	certMu  sync.RWMutex
	ticker  *time.Ticker
	keypair *tls.Certificate
	serial  *string
}

// NewTLSRotater is used to create a TLSRotater later to be started with Start.
//
// To be used like this for clients:
//  rotater := tlsrotater.NewTLSRotater(client, "outproxy", []string{"localhost"})
//  if err := rotater.Start(); err != nil {
//  	panic(err)
//  }
//  defer rotater.Stop()
//  log.Println("Created keypair reloader")
//  	tlsConfig := tls.Config{
//  	RootCAs:              rotater.CACertPool,
//  	GetClientCertificate: rotater.GetClientCertificateFunc(),
//  }
func NewTLSRotater(client *vaultapi.Client, commonName string, altNames []string) *TLSRotater {
	return &TLSRotater{
		commonName: commonName,
		client:     client,
	}
}

func (rotater *TLSRotater) refresh() error {
	rotater.certMu.Lock()
	defer rotater.certMu.Unlock()
	previousSerial := rotater.serial

	// Retrieve new keypair
	params := make(map[string]interface{})
	params["common_name"] = rotater.commonName
	params["alt_names"] = "localhost"
	params["ttl"] = "5m"
	secret, err := rotater.client.Logical().Write("pki/issue/"+rotater.commonName, params)
	if err != nil {
		return err
	}

	// Extract the data
	certificateContents := []byte(secret.Data["certificate"].(string))
	privateKeyContents := []byte(secret.Data["private_key"].(string))
	if keypair, err := tls.X509KeyPair(certificateContents, privateKeyContents); err == nil {
		var caChainContents []byte
		if secret.Data["ca_chain"] != nil {
			caChainContents = []byte(secret.Data["ca_chain"].(string))
		} else {
			caChainContents = []byte(secret.Data["issuing_ca"].(string))
		}
		rotater.CACertPool = x509.NewCertPool()
		if ok := rotater.CACertPool.AppendCertsFromPEM(caChainContents); !ok {
			return fmt.Errorf("Error loading CA chain")
		}
		newSerial := secret.Data["serial_number"].(string)
		rotater.serial = &newSerial
		rotater.keypair = &keypair
	} else {
		return fmt.Errorf("Couldn't load cert: %v", err)
	}

	// Revoke the previous cert
	if previousSerial != nil {
		revokeParams := make(map[string]interface{})
		revokeParams["serial_number"] = *previousSerial
		secret, err := rotater.client.Logical().Write("pki/revoke", revokeParams)
		if err != nil {
			return fmt.Errorf("Couldn't revoke previous certificate: %v", err)
		}
		revocationTimeNumber, err := secret.Data["revocation_time"].(json.Number).Int64()
		if err != nil {
			return fmt.Errorf("Couldn't parse revocation time number: %v", err)
		}
		log.Printf("Old certificate revoked at %v\n", time.Unix(revocationTimeNumber, 0))
		tidyParams := make(map[string]interface{})
		tidyParams["tidy_cert_store"] = true
		tidyParams["tidy_revocation_list"] = true
		tidyParams["safety_buffer"] = (5 * time.Minute).String()
		rotater.client.Logical().Write("pki/tidy", tidyParams)
	}
	log.Printf("Refreshed certificate. New serial: %v\n", *rotater.serial)

	return nil
}

func (rotater *TLSRotater) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		rotater.certMu.RLock()
		defer rotater.certMu.RUnlock()
		return rotater.keypair, nil
	}
}

func (rotater *TLSRotater) GetClientCertificateFunc() func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		rotater.certMu.RLock()
		defer rotater.certMu.RUnlock()
		return rotater.keypair, nil
	}
}

func (rotater *TLSRotater) Start() error {
	err := rotater.refresh()
	if err != nil {
		return fmt.Errorf("Error during start: #%v", err)
	}
	multiplier := 0.7 + 0.2*rand.Float64()
	ticker := time.NewTicker(time.Duration(int64(multiplier * float64(time.Minute.Nanoseconds()))))
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := rotater.refresh(); err != nil {
					fmt.Fprintf(os.Stderr, "Error while refreshing certs: %v\n", err)
				}
			}
		}
	}()
	return nil
}

func (rotater *TLSRotater) Stop() {
	if rotater.ticker != nil {
		rotater.ticker.Stop()
	}
}
