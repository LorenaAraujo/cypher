package main

import (
  "fmt"
  "crypto/des"
  "crypto/cipher"
  "encoding/hex"
  "bytes"
)

func main() {
  key := []byte("123456781234567812345678")
  iv := []byte("43218765")
  plaintext := []byte("Hello WoRLDA") // Hello Wo = 8 bytes.

  b := hex.EncodeToString(plaintext)
  fmt.Println(b)

  //encrypt
  result, err := TripleDesEncrypt(plaintext, key,iv)
  if err != nil {
    fmt.Println(err)
  }
  b = hex.EncodeToString(result)
  fmt.Println(b)

  //decrypt
  result, err = tripleDesDecrypt(result, key,iv)
  if err != nil {
    fmt.Println(err)
  }
  b = hex.EncodeToString(result)
  fmt.Println(b)
}

// 3DES decryption
func tripleDesDecrypt(crypted, key, iv []byte) ([]byte, error) {
  block, err := des.NewTripleDESCipher(key)
  if err != nil {
    fmt.Println(err.Error())
    return nil, err
  }
  blockMode := cipher.NewCBCDecrypter(block, []byte(iv))
  origData := make([]byte, len(crypted))
  // origData := crypted
  blockMode.CryptBlocks(origData, crypted)
  origData = PKCS5UnPadding(origData)
  // origData = ZeroUnPadding(origData)
  return origData, nil
}

// 3DES encryption
func TripleDesEncrypt(origData, key, iv []byte) ([]byte, error) {
  block, err := des.NewTripleDESCipher(key)
  if err != nil {
    return nil, err
  }
  origData = PKCS5Padding(origData, block.BlockSize())
  // origData = ZeroPadding(origData, block.BlockSize())
  blockMode := cipher.NewCBCEncrypter(block, []byte(iv))
  crypted := make([]byte, len(origData))
  blockMode.CryptBlocks(crypted, origData)
  return crypted, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
  padding := blockSize - len(ciphertext)%blockSize
  padtext := bytes.Repeat([]byte{byte(padding)}, padding)
  return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
  length := len(origData)
  // remove the last byte unpadding times
  unpadding := int(origData[length-1])
  return origData[:(length - unpadding)]
}