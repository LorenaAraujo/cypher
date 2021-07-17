package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
)

func main() {
	data := []byte("abcdefgABCDEF")
	key := []byte("12345678")
	iv := []byte("43218765")

	b := hex.EncodeToString(data)
	fmt.Println(b)
	
	//encrypt
	result, err := DesCBCEncrypt(data, key, iv)
	if err != nil {
		fmt.Println(err)
	}
	b = hex.EncodeToString(result)
	fmt.Println(b)
	//decrypt
	result, err = DesCBCDecrypt(result, key, iv)
	if err != nil {
		fmt.Println(err)
	}
	b = hex.EncodeToString(result)
	fmt.Println(b)

}

func DesCBCEncrypt(data, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cryptText, data)
	return cryptText, nil
}

func DesCBCDecrypt(data, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < des.BlockSize {
		panic("ciphertext too short")
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	cryptText := make([]byte, len(data))
	blockMode.CryptBlocks(cryptText, data)
	cryptText = pkcs5Depadding(cryptText, des.BlockSize)
	return cryptText, nil
}

func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func pkcs5Depadding(cipherText []byte, blockSize int) []byte {
	padding := cipherText[len(cipherText)-1]
	out := bytes.Split(cipherText, []byte{padding})
	return out[0][:]
}
