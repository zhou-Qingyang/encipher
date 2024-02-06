package main

import (
	"encipher/models"
	"fmt"
	"strconv"
)

// sm9 国密算法
func main() {
	input := []int64{0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210}
	mk := GetKArray(input) // k0 k1 k2 k3
	// rk0 = k4 = k0 k1 k2 k3
	// rk1 = k5 = k4 k1 k2 k3
	rk := make([]int64, 32)
	fresult := make([]int64, 32)
	for i := 0; i < 32; i++ {
		temprk := GetRK(mk, i)
		rk[i] = temprk
		mk = append(mk[1:], temprk)
		// 刚进来的时候 X: x0 x1 x2 x3 rk0 x4
		// 第二次循环 x1,x2,x3,x4 rk1
		frest := F(input, temprk)
		fresult[i] = frest
		fmt.Printf("rk[%d]:%08X X[%d]:%X\n", i, temprk, i, frest)
		input = append(input[1:], frest)
	}
	fmt.Printf("加密密文:%08X %08X %08X %08X\n", fresult[len(fresult)-1], fresult[len(fresult)-2], fresult[len(fresult)-3], fresult[len(fresult)-4])
	fmt.Println("--------------------分割线------------------")
	encipherText := []int64{0x681EDF34, 0xD206965E, 0x86B3E94F, 0x536E4246}
	//解密的时候顺序使用 rk31 rk30 rk29 ...
	for i := 31; i >= 0; i-- {
		fmt.Printf("rk[%d]:%08X X[%d]:%X\n", i, rk[i], i, F(encipherText, rk[i]))
		encipherText = append(encipherText[1:], F(encipherText, rk[i]))
	}
}

func GetXArray(x []string) []int64 {
	res := make([]int64, 4)
	for i := 0; i < 4; i++ {
		num1, _ := strconv.ParseInt(x[i], 16, 64) // 将十六进制数2转换为整数
		res[i] = num1
	}
	return res
}

// 拿到K数组 k0 k1 k2 k3
func GetKArray(mk []int64) []int64 {
	res := make([]int64, 4)
	for i := 0; i < 4; i++ {
		xorResult := mk[i] ^ models.FK[i]
		res[i] = xorResult
	}
	return res
}

// 获取RK
func GetRK(data []int64, index int) int64 {
	//rk0  = k0 ^ T'(k1 ^ k2 ^ k3 ^ CK0) = k4  公式
	//rk27 = k31 = k27 ^ (k28 ^ k29 ^ k30 ^CK27)
	//rk1  = k1 ^ T'(k2 ^ k3 ^ k4 ^ CK1)  公式
	var item int64
	item = data[1] ^ data[2] ^ data[3] ^ int64(models.CK[index])
	LpieData := TaoFunction(item)
	return data[0] ^ LPie(LpieData)
}

// 通用
func TaoFunction(data int64) int64 {
	var res int64
	for i := 0; i < 4; i++ {
		low8bits := data & 0xFF // 取data的低8位
		result := low8bits      // 将低8位转换为int64类型
		temp := int64(models.SBOX[result])
		data = data >> 8
		switch i {
		case 0:
			res = res | temp
		case 1:
			res = res | (temp << 8)
		case 2:
			res = res | (temp << 16)
		case 3:
			res = res | (temp << 24)
		}
	}
	return res
}

// LPie
func LPie(value int64) int64 {
	// 公式 L'(B) = B ^ (B << 13) ^	(B << 23) 循环左移
	//value, _ := strconv.ParseInt(data, 16, 64)
	// 左移13位，高位舍弃，低位补0
	B1 := (value << 13) | (value >> (32 - 13))
	// 只保留低32位
	B2 := (value << 23) | (value >> (32 - 23))
	res := value ^ B1 ^ B2
	res &= 0xffffffff
	return res
}

func L(value int64) int64 {
	// 公式 L(B) = B ^ (B << 2) ^(B << 10)^ (B << 18) ^	(B << 24)循环左移
	// 左移13位，高位舍弃，低位补0
	B1 := (value << 2) | (value >> (32 - 2))
	// 只保留低32位
	B2 := (value << 10) | (value >> (32 - 10))
	B3 := (value << 18) | (value >> (32 - 18))
	B4 := (value << 24) | (value >> (32 - 24))
	res := value ^ B1 ^ B2 ^ B3 ^ B4
	res &= 0xffffffff
	return res
}

func F(xArr []int64, rk int64) int64 {
	// X4 =  X0 ^ T(X1 ^ X2 ^ X3 ^ rk)  公式
	//xFormat := GetXArray(xArr)
	taoData := xArr[1] ^ xArr[2] ^ xArr[3] ^ rk
	ldata := TaoFunction(taoData)
	return xArr[0] ^ L(ldata)
}
