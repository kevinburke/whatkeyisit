package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("usage: whatkeyisit <file|key as string>")
	}
	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	more := true
	rest := data
	for more {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		more = len(rest) > 0
		if block == nil {
			log.Fatal("no PEM block found")
		}
		pk, err := x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			publickey := pk.Public().(*ecdsa.PublicKey)
			fmt.Printf("%s is a ECDSA private key, generated with the %s curve.\n", flag.Arg(0), publickey.Curve.Params().Name)
			continue
		}
		rpk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			fmt.Printf("%s is a RSA private key, with %d bits.\n", flag.Arg(0), rpk.D.BitLen())
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			fmt.Printf("%s is a certificate, using the %s algorithm.\n", flag.Arg(0), cert.SignatureAlgorithm)
			fmt.Printf("The certificate is valid for hosts %s.\n", strings.Join(cert.DNSNames, ", "))
			fmt.Printf("It expires on %s.\n", cert.NotAfter.Format("January 02, 2006"))
			continue
		}
		publickey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			switch tkey := publickey.(type) {
			case *ecdsa.PublicKey:
				fmt.Printf("%s is a ECDSA public key, generated with the %s curve.\n", flag.Arg(0), tkey.Curve.Params().Name)
			case *rsa.PublicKey:
				fmt.Printf("%s is a RSA public key.\n", flag.Arg(0))
			case *dsa.PublicKey:
				fmt.Printf("%s is a DSA public key.\n", flag.Arg(0))
			}
			continue
		}
	}
}
