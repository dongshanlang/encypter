/**
 * @Author: lixiumin
 * @E-Mail: lixiuminmxl@163.com
 * @Date: 2022/7/18 4:57 PM
 * @Desc:
 */

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func generateHMAC(src, key []byte) []byte {
	hasher := hmac.New(sha256.New, key)
	hasher.Write(src)
	return hasher.Sum(nil)
}

func main() {
	src := []byte("墙角数枝梅，凌寒独自开。")
	key := []byte("0123456789")
	fmt.Printf("hash code: %x\n", generateHMAC(src, key))
}
