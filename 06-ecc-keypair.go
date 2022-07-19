/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/19 10:39 AM
 * @Desc:
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func generateEccKeyPair() {
	//1.选择一个椭圆曲线
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	derText, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	block1 := pem.Block{
		Type:    "ECC PRIVATE KEY",
		Headers: nil,
		Bytes:   derText,
	}
	fileHandler, err := os.Create("./eccPrivateKey.pem")
	err = pem.Encode(fileHandler, &block1)
	if err != nil {
		panic(err)
	}
	fmt.Println("+++++++++++++++++++++")
	publicKey := privateKey.PublicKey
	derPublicKeyText, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	blockPublicKey := pem.Block{
		Type:    "ECC PUBLIC KEY",
		Headers: nil,
		Bytes:   derPublicKeyText,
	}
	filePublicKeyHandler, err := os.Create("./eccPublicKey.pem")
	if err != nil {
		panic(err)
	}
	err = pem.Encode(filePublicKeyHandler, &blockPublicKey)
	if err != nil {
		panic(err)
	}
}
func main() {
	generateEccKeyPair()
}
