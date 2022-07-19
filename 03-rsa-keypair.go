/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/15 7:20 PM
 * @Desc:
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	PrivateFile = "./privateRSAKey.pem"
	PublicFile  = "./publicRSAKey.pem"
)

//生成私钥
func generateKeyPair(bits int) error {
	//generateKey
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	priDerText := x509.MarshalPKCS1PrivateKey(privateKey)

	//3.创建block，代表PEM编码的结构
	block := pem.Block{
		Type:    "BJ RSA PRIVATE KEY",
		Headers: nil,        //可选信息，包括加密方式等
		Bytes:   priDerText, //私钥编码后的数据
	}
	//4。写磁盘
	fileHandler1, err := os.Create(PrivateFile)
	if err != nil {
		return err
	}
	defer fileHandler1.Close()
	err = pem.Encode(fileHandler1, &block)
	if err != nil {
		return err
	}
	fmt.Println("++++++++++gen pub key++++++++++++")
	//1.获取私钥
	publicKey := privateKey.PublicKey //
	//2。对私钥编码处理
	publicKeyDerText := x509.MarshalPKCS1PublicKey(&publicKey)
	///3。创建block
	blockPub := pem.Block{
		Type:    "BJ RSA PUB",
		Headers: nil,
		Bytes:   publicKeyDerText,
	}
	//4。写到磁盘
	fileHandler2, err := os.Create(PublicFile)
	if err != nil {
		return err
	}
	defer fileHandler2.Close()
	err = pem.Encode(fileHandler2, &blockPub)
	if err != nil {
		return err
	}
	return nil
}
func main() {
	err := generateKeyPair(2048)
	if err != nil {
		fmt.Println(err)
	}
}
