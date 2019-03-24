package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("usage: extractprivatekey <file|key as string>")
	}
	flag.Arg(0)
	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	rest := data
	var block *pem.Block
	block, rest = pem.Decode(rest)
	//more = len(rest) > 0
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		der, err := x509.MarshalPKIXPublicKey(pk.Public())
		if err != nil {
			log.Fatal(err)
		}
		enc := make([]byte, base64.StdEncoding.EncodedLen(len(der)))
		base64.StdEncoding.Encode(enc, der)
		l := len(enc)
		for l > 0 {
			if l > 64 {
				fmt.Println(string(enc[:64]))
				enc = enc[64:]
				l = len(enc)
			} else {
				fmt.Println(string(enc[:]))
				break
			}
		}
	}
}
