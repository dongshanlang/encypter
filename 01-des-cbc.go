/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/15 11:55 AM
 * @Desc:
 */

package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

//输入明文，密钥
func decCBCEncrypt(src, key []byte) []byte {
	//todo
	fmt.Println("begin encrypt: ", string(src))
	//1.创建并返回一个使用des算法的cipher.Block接口
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2。数据填充
	src = paddingInfo(src, block.BlockSize())
	//3。引入CBC，返回一个密码分组连接模式，底层用b加密的blockMode接口，出示响亮iv的长度必须等于b的块尺寸。
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//dst := make([]byte, len(src))
	blockMode.CryptBlocks(src, src)

	fmt.Println("end encrypt: ", src)
	return src
}

//填充函数，输入明文，分组长度，输出填充后的数据
func paddingInfo(src []byte, blockSize int) []byte {
	//1.计算明文长度
	length := len(src)
	//2。计算需要填充的数据
	remains := length % blockSize
	paddingNumber := blockSize - remains
	//3。把需要填充的数值转换为字符
	s1 := byte(paddingNumber)

	//4。把字符拼成数组
	s2 := bytes.Repeat([]byte{s1}, paddingNumber)

	//5把拼成的数组追加到src后面
	sNew := append(src, s2...)
	//6返回新的数组
	return sNew
}

//解密
//输入明文，密钥
func decCBCDecrypt(src, key []byte) []byte {
	fmt.Println("begin decrypt: ", string(src))
	//1.创建并返回一个使用des算法的cipher.Block接口
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//2。引入CBC，返回一个密码分组连接模式，底层用b加密的blockMode接口，出示响亮iv的长度必须等于b的块尺寸。
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(src, src)

	////3。数据去除
	src = unPaddingInfo(src, block.BlockSize())
	fmt.Println("end decrypt: ", src)
	return src
}

//去除填充
func unPaddingInfo(src []byte, blockSize int) []byte {
	//1.计算密文长度
	length := len(src)
	if length == 0 {
		return []byte{}
	}
	//2。获取最后一个字符
	lastByte := src[length-1]
	//3。将字符转为数字
	lastPaddingNumber := int(lastByte)
	//4。切片截取数据
	return src[0 : length-lastPaddingNumber]
}

func main() {
	src := []byte("落霞与孤鹜齐飞")
	key := []byte("12345678")
	encrypted := decCBCEncrypt(src, key)

	fmt.Println("encrypted: ", string(encrypted))
	fmt.Println("=================================")
	decrypted := decCBCDecrypt(encrypted, key)
	fmt.Println("decrypted: ", string(decrypted))
}
