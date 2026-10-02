// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Initialize creates a new directory with config.json, localhost development
// TLS credentials, a development CA certificate and separate random token files.
// Existing directories are never overwritten. The CA private key is not saved.
func Initialize(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("initialization directory is empty")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.New("could not resolve initialization directory")
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", fmt.Errorf("create new initialization directory: %w", err)
	}
	var owned []string
	done := false
	defer func() {
		if !done {
			for _, path := range owned {
				_ = os.Remove(path)
			}
			_ = os.Remove(dir)
		}
	}()
	ca, cert, key, err := developmentTLS()
	if err != nil {
		return "", errors.New("could not generate development TLS credentials")
	}
	admin, err := randomToken()
	if err != nil {
		return "", errors.New("could not generate administrator token")
	}
	user, err := randomToken()
	if err != nil {
		return "", errors.New("could not generate user token")
	}
	cfg := Default()
	cfg.TLSCert, cfg.TLSKey = "server.crt", "server.key"
	cfg.AdminTokenHash, cfg.UserTokenHash = tokenHash(admin), tokenHash(user)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", errors.New("could not encode initial configuration")
	}
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"ca.crt", ca},
		{"server.crt", cert},
		{"server.key", key},
		{"admin.token", []byte(admin + "\n")},
		{"user.token", []byte(user + "\n")},
		{"config.json", append(data, '\n')},
	} {
		path := filepath.Join(dir, file.name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", errors.New("could not create initial configuration file")
		}
		owned = append(owned, path)
		_, writeErr := f.Write(file.data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if errors.Join(writeErr, syncErr, closeErr) != nil {
			return "", errors.New("could not persist initial configuration file")
		}
	}
	directory, err := os.Open(dir)
	if err != nil {
		return "", errors.New("could not open initialization directory")
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if errors.Join(syncErr, closeErr) != nil {
		return "", errors.New("could not persist initialization directory")
	}
	done = true
	return filepath.Join(dir, "config.json"), nil
}

func randomToken() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func tokenHash(token string) string {
	hash := sha512.Sum512([]byte(token))
	return hex.EncodeToString(hash[:])
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max.Sub(max, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func developmentTLS() (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	caSerial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	leafSerial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "PCCS local development CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// CreateCertificate generates the CA's subject key identifier in DER,
	// without updating the template. Use the parsed CA as the parent so the
	// leaf receives the authority key identifier required by strict clients.
	issuer, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), nil
}
