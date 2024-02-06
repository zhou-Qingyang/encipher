package main

import (
	"encipher/models"
	"encoding/hex"
	"fmt"
	"github.com/xlcetc/cryptogm/sm/sm4"
	"testing"
)

func TestTaoFunctiont(t *testing.T) {
	models.GVA_DB = models.GormMysql()
	var lamb models.Lamb
	if err := models.GVA_DB.Model(models.Lamb{}).First(&lamb, 1).Error; err != nil {
		return
	}
	fmt.Println("数据库数据", lamb.JuanSheHao)

	plaintext := lamb.JuanSheHao
	key := "0123456789abcdef" // 16字节的密钥，需要根据实际情况设置
	//默认密钥
	ciphertext, err := encryptString(key, plaintext)
	if err != nil {
		fmt.Println("加密失败:", err)
		return
	}
	fmt.Println("加密后的结果:", ciphertext)

	block, _ := sm4.NewCipher([]byte(key))
	mingText := make([]byte, len(ciphertext)/2)
	// 解密操作
	decodedCiphertext, _ := hex.DecodeString(ciphertext)
	block.Decrypt(mingText, decodedCiphertext)
	// 输出解密结果
	fmt.Printf("解密的结果: %s\n", mingText)
	newSheep := models.Lamb{
		JuanSheHao:   string(mingText),
		TiZhong:      "12千克",
		XiongShen:    "完善",
		GuanWei:      "完善",
		TiXingWaiMao: "完善",
		BeiZhu:       "完善",
		Father:       "完善",
		Mather:       "完善",
	}
	if err := models.GVA_DB.Create(&newSheep).Error; err != nil {
		return
	}
	fmt.Println("新增数据成功")
}

func encryptString(key, plaintext string) (string, error) {
	block, err := sm4.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, []byte(plaintext))
	return hex.EncodeToString(ciphertext), nil
}
