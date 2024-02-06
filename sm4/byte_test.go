package main

import (
	"fmt"
	"testing"
)

func TestBytesSplit(t *testing.T) {
	octal := 03500277
	fmt.Printf("%c", octal)
	//str := "这个一个非常由于的a2"
	//var builder strings.Builder
	//bytes := []byte(str)
	//for _, b := range bytes {
	//	octal := fmt.Sprintf("%#o", b)
	//	builder.Write([]byte(octal))
	//}
	//
	//length := len(builder.String())
	//fmt.Println(length)
	//
	//paddingCount := (128 - length%128) % 128
	//for i := 0; i < paddingCount; i++ {
	//	builder.Write([]byte("0"))
	//}
	//
	//fmt.Println(builder.String())
	//for i := 0; i < (length/128)+1; i++ {
	//	temp := builder.String()[i*128 : (i+1)*128]
	//	fmt.Printf("%s \n", temp)
	//}
}
