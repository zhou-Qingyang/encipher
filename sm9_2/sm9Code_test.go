package sm9_2

import (
	"crypto/rand"
	"encipher/models"
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	models.GVA_DB = models.GormMysql()
	var lamb models.Lamb
	if err := models.GVA_DB.Model(models.Lamb{}).First(&lamb, 1).Error; err != nil {
		return
	}
	fmt.Println("数据库数据", lamb.JuanSheHao)
	plaintext := []byte(lamb.JuanSheHao)
	//plaintext := []byte("Chinese standard")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("加密的数据: %s\n", string(cipher))
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(userKey, uid, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
	}
	fmt.Printf("解密的明文 : %s\n", got)
	newSheep := models.Lamb{
		JuanSheHao:   string(got),
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
