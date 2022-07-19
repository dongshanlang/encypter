/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/15 7:55 PM
 * @Desc:
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func rsaPubEncrypt(filename string, plainText []byte) ([]byte, error) {
	//1.公钥文件，读取公要信息，pem encode 的数据
	info, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}
	//2。pemdecode， 得到block中的der编码数据
	block, _ := pem.Decode(info)

	//3。解码der，得到公钥
	derText := block.Bytes
	publicKey, err := x509.ParsePKCS1PublicKey(derText)
	if err != nil {
		return []byte{}, err
	}
	//4。公钥加密
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
}
func rsaPrivateKeyDecrypt(filename string, cipherData []byte) ([]byte, error) {
	//1.公钥文件，读取公要信息，pem encode 的数据
	info, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}
	//2。pemdecode， 得到block中的der编码数据
	block, _ := pem.Decode(info)

	//3。解码der，得到公钥
	derText := block.Bytes
	privateKey, err := x509.ParsePKCS1PrivateKey(derText)
	if err != nil {
		return []byte{}, err
	}
	//4。公钥加密
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherData)
}
func main() {
	src := []byte("落霞与孤鹜齐飞,qiu")
	//key := []byte("1234567812345678")
	cipherDate, err := rsaPubEncrypt("./publicRSAKey.pem", src)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(cipherDate))

	decryptDate, err := rsaPrivateKeyDecrypt("./privateRSAKey.pem", cipherDate)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decryptDate))
}
