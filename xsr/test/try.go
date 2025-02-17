package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

// PKCS7 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// 去除 PKCS7 填充
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data length is zero")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:length-padding], nil
}

// AES 加密
func aesEncrypt(plainText, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	plainText = pkcs7Padding(plainText, blockSize)

	cipherText := make([]byte, blockSize+len(plainText))
	iv := cipherText[:blockSize]

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], plainText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// AES 解密
func aesDecrypt(cipherText string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return "", fmt.Errorf("cipher text too short")
	}

	iv := data[:blockSize]
	data = data[blockSize:]

	if len(data)%blockSize != 0 {
		return "", fmt.Errorf("cipher text is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	data, err = pkcs7Unpadding(data)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func main() {
	data := []byte("这是一个需要签名的重要消息")
	hashedData := sha256.Sum256(data)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02 15:04:05.000000")
	fmt.Println("Current Time with Microseconds: ", formattedTime)
	// 使用私钥创建签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedData[:])
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashedData[:], signature)
	if err != nil {
		panic(err)
	}
	currentTime = time.Now()
	formattedTime = currentTime.Format("2006-01-02 15:04:05.000000")
	fmt.Println("Current Time with Microseconds: ", formattedTime)
}
