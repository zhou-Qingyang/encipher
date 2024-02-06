package sm9

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"github.com/xlcetc/cryptogm/elliptic/sm9curve"
	"github.com/xlcetc/cryptogm/sm/sm3"
	"io"
	"math"
	"math/big"
)

type hashMode int

const (
	// hashmode used in h1: 0x01
	H1 hashMode = iota + 1
	// hashmode used in h2: 0x02
	H2
)

// 主密钥
type MasterKey struct {
	Msk *big.Int
	MasterPubKey
}

// 主公钥
type MasterPubKey struct {
	Mpk *sm9curve.G1
}

// UserKey  用户密钥
type UserKey struct {
	Sk *sm9curve.G2
}

var (
	counter  uint32 = 1
	hashSize        = sm3.Size
	result   []byte
)

// KDF 使用 SM3 进行密钥派生
func KDF(seed []byte, outputLen int) ([]byte, error) {
	for len(result) < outputLen {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		counter++
		input := append(seed, counterBytes...)
		hash := sm3.New().Sum(input)
		result = append(result, hash[:]...)
	}
	return result[:outputLen], nil
}

// hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func hash(z []byte, n *big.Int, h hashMode) *big.Int {
	//counter
	ct := 1
	hlen := 8 * int(math.Ceil(float64(5*n.BitLen()/32)))

	var ha []byte
	for i := 0; i < int(math.Ceil(float64(hlen/256))); i++ {
		msg := append([]byte{byte(h)}, z...)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(ct))
		msg = append(msg, buf...)
		hai := sm3.SumSM3(msg)
		ct++
		if float64(hlen)/256 == float64(int64(hlen/256)) && i == int(math.Ceil(float64(hlen/256)))-1 {
			ha = append(ha, hai[:(hlen-256*int(math.Floor(float64(hlen/256))))/32]...)
		} else {
			ha = append(ha, hai[:]...)
		}
	}
	bn := new(big.Int).SetBytes(ha)
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	bn.Mod(bn, nMinus1)
	bn.Add(bn, one)
	return bn
}

// generate rand numbers in [1,n-1].n是SM9曲线的阶，用于限制随机数的范围
func randFieldElement(rand io.Reader, n *big.Int) (k *big.Int, err error) {
	one := big.NewInt(1)
	b := make([]byte, 256/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	nMinus1 := new(big.Int).Sub(n, one)
	k.Mod(k, nMinus1)
	return
}

// generate master key for KGC(Key Generate Center).  生成主密钥
func MasterKeyGen(rand io.Reader) (mk *MasterKey, err error) {

	s, err := randFieldElement(rand, sm9curve.Order)
	if err != nil {
		return nil, errors.Errorf("gen rand num err:%s", err)
	}
	mk = new(MasterKey)

	mk.Msk = new(big.Int).Set(s)
	//[s]P1
	mk.Mpk = new(sm9curve.G1).ScalarBaseMult(s)
	return
}

// 生成用户密钥的方法
func UserKeyGen(mk *MasterKey, id []byte, hid byte) (uk *UserKey, err error) {
	id = append(id, hid)
	n := sm9curve.Order //群的阶级

	// t1 = H1(IDA || hid,N)
	t1 := hash(id, n, H1)

	// t1 = t1 + S
	t1.Add(t1, mk.Msk)

	//if t1 = 0, we need to regenerate the master key.
	if t1.BitLen() == 0 || t1.Cmp(n) == 0 {
		return nil, errors.New("need to regen mk!")
	}

	// t1 = t1 % n
	t1.ModInverse(t1, n)

	//t2 = s*t1^-1
	t2 := new(big.Int).Mul(mk.Msk, t1)

	uk = new(UserKey)

	//[t2]P2
	uk.Sk = new(sm9curve.G2).ScalarBaseMult(t2)
	return
}

// SM9主公钥、用户ID、ID和明文作为输入
// Encrypt encrypts plaintext using SM9 algorithm.
func Encrypt(mpk *MasterPubKey, id []byte, hid byte, mes []byte) ([]byte, error) {
	n := sm9curve.Order //群的阶级
	//  hb := H1(IDb || hid,n)
	id = append(id, hid)
	hb := hash(id, n, H1)
	r, err := randFieldElement(rand.Reader, n)
	if err != nil {
		return nil, errors.Errorf("failed to generate random number: %s", err)
	}
	// Qb := [hb]P1 + PubKey
	Qb := new(sm9curve.G1).ScalarBaseMult(hb)
	Qb.Add(Qb, mpk.Mpk)

	// g = e(Pub,P2)
	g := sm9curve.Pair(mpk.Mpk, sm9curve.Gen2)

	// w = g ^ r
	w := new(sm9curve.GT).ScalarMult(g, r)

	// C1 = [r]Qb
	C1 := new(sm9curve.G1).ScalarMult(Qb, r)

	c1Bytes := C1.Marshal()
	wBytes := w.Marshal()

	//K1 || K2 = KDF(C1 || w || IDb,klen)
	input := append(append(c1Bytes, wBytes...), id...)
	kdf, err := KDF(input, 128)
	if err != nil {
		fmt.Println("kdf生成失败,出现问题")
	}
	k1Bytes := kdf[:len(mes)] // 获取前 16 个字节
	k2Bytes := kdf[len(mes):]

	if len(k1Bytes) < aes.BlockSize {
		padLen := aes.BlockSize - len(k1Bytes)
		pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
		k1Bytes = append(k1Bytes, pad...)
	}
	// 补全  C2 = Enc(K1,mes)
	blockCipher, err := aes.NewCipher(k1Bytes)
	if err != nil {
		return nil, errors.Errorf("failed to create AES cipher: %s", err)
	}
	c2Bytes := make([]byte, len(mes))
	blockCipher.Encrypt(c2Bytes, mes)

	// 补全  C3 = MAC(K2,C2)
	mac := hmac.New(sha256.New, k2Bytes)
	mac.Write(c2Bytes)
	c3Bytes := mac.Sum(nil)

	// 将 C1, C2 和 C3 组合成密文
	ciphertext := append(c1Bytes, c2Bytes...)
	ciphertext = append(ciphertext, c3Bytes...)

	return ciphertext, nil
}

//
//func Decrypt(msk *MasterSecKey, id []byte, hid byte, ciphertext []byte) ([]byte, error) {
//	// 解析密文
//	if len(ciphertext) <= 16 {
//		return nil, errors.New("invalid ciphertext")
//	}
//	c1Bytes := ciphertext[:8]
//	c2Bytes := ciphertext[8 : len(ciphertext)-16]
//	c3Bytes := ciphertext[len(ciphertext)-16:]
//
//	// 计算派生密钥
//	wBytes := msk.w(idsToBytes(id))
//	input := append(append(c1Bytes, wBytes...), id...)
//	kdf, err := KDF(input, 128)
//	if err != nil {
//		return nil, errors.Errorf("failed to derive key: %s", err)
//	}
//	k1Bytes := kdf[:16]
//	k2Bytes := kdf[16:]
//
//	// 解密和认证
//	blockCipher, err := aes.NewCipher(k1Bytes)
//	if err != nil {
//		return nil, errors.Errorf("failed to create AES cipher: %s", err)
//	}
//	mesBytes := make([]byte, len(c2Bytes))
//	blockCipher.Decrypt(mesBytes, c2Bytes)
//
//	mac := hmac.New(sha256.New, k2Bytes)
//	mac.Write(c1Bytes)
//	mac.Write(c2Bytes)
//	expectedC3 := mac.Sum(nil)
//	if !hmac.Equal(expectedC3, c3Bytes) {
//		return nil, errors.New("authentication failed")
//	}
//
//	return mesBytes, nil
//}
