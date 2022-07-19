/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/15 4:24 PM
 * @Desc:
 */

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func aesCTREncrypt(src, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	fmt.Println("aes block size: ", block.BlockSize())
	//2。选择分组模式
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3.加密操作
	stream.XORKeyStream(src, src)
	return src

}
func aesCTRDecrypt(src, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	fmt.Println("aes block size: ", block.BlockSize())
	//2。选择分组模式
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3.加密操作
	stream.XORKeyStream(src, src)
	return src
}
func main() {
	src := []byte("落霞与孤鹜齐飞,qiu")
	key := []byte("1234567812345678")
	cipherDate := aesCTREncrypt(src, key)
	fmt.Println(string(cipherDate))

	decryptDate := aesCTRDecrypt(src, key)
	fmt.Println(string(decryptDate))
}
