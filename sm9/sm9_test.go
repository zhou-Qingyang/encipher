package sm9

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSM9Generate(t *testing.T) {
	// 生成一个主密钥
	mk, err := MasterKeyGen(rand.Reader)
	if err != nil {
		t.Errorf("mk gen failed:%s", err)
		return
	}
	var hid byte = 1
	var uid = []byte("Alice") //这个其实就是用户公钥
	msg := []byte("message")
	ciphertext, err := Encrypt(&mk.MasterPubKey, uid, hid, msg)
	if err != nil {
		t.Errorf("mk gen failed:%s", err)
		return
	}
	fmt.Println("加密文字", ciphertext)
}
