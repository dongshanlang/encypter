/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/19 2:58 PM
 * @Desc:
 */

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
)

type Signature struct {
	R *big.Int
	S *big.Int
}

func eccSignData(filename string, src []byte) (Signature, error) {
	//1.read private key
	info, err := ioutil.ReadFile(filename)
	if err != nil {
		return Signature{}, err
	}
	//2.pem decode, get der data from block
	block, _ := pem.Decode(info)
	//3. decode der, get private key
	derText := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(derText)
	if err != nil {
		return Signature{}, err
	}
	//4.get hash message authentication code
	hash := sha256.Sum256(src)

	//5.sign data
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return Signature{}, err
	}
	return Signature{r, s}, nil
}

func eccVerifySignature(filename string, src []byte, sig Signature) error {
	//1.get public key
	info, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	//2. pem decode, get block der data
	block, _ := pem.Decode(info)

	//3.decode der, get public key
	derText := block.Bytes

	publicKeyInterface, err := x509.ParsePKIXPublicKey(derText)
	if err != nil {
		return err
	}
	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("transform ecdsa.PublicKey failed")
	}
	//4.get hash message authentication code of src
	hash := sha256.Sum256(src)

	//5. verify
	isValid := ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)
	if isValid {
		return nil
	}
	return errors.New("verify failed")
}

func main() {
	src := []byte("苦海无涯苦作舟")
	sig, err := eccSignData("./eccPrivateKey.pem", src)
	if err != nil {
		fmt.Println("err: ", err)
		return
	}
	fmt.Println("sign data success: ", sig)

	fmt.Println("+++++++++++++verify+++++++++++++")
	src1 := []byte("苦海无涯苦作舟1")
	err = eccVerifySignature("./eccPublicKey.pem", src1, sig)
	if err != nil {
		fmt.Println("verify failed")
		return
	}
	fmt.Println("verify OK")

}
