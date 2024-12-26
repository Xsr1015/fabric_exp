package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"github.com/klauspost/reedsolomon"
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
	key := []byte("thisis32bitlongpassphrase!!!!!!!") // 32 字节密钥
	plainText := "Hello, this is a secret message!"

	// 加密
	encrypted, err := aesEncrypt([]byte(plainText), key)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		return
	}
	fmt.Printf("Encrypted: %s\n", encrypted)

	// 解密
	decrypted, err := aesDecrypt(encrypted, key)
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		return
	}
	fmt.Printf("Decrypted: %s\n", decrypted)

	//reed-solomon
	// 输入数据 (可以是任何数据，比如字符串或者字节)
	data := []byte("thisis32bitlongpassphrase!!!!!!!")

	// 设置编码参数
	// 数据块大小
	dataShards := 8
	// 冗余块大小 (parity shards)
	parityShards := 4
	//totalShards := dataShards + parityShards

	// 创建 Reed-Solomon 编码器
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		log.Fatalf("Error creating Reed-Solomon encoder: %v", err)
	}

	// 编码
	// 创建一个新的切片，大小为 n 个数据块
	blocks, err := enc.Split(data)
	if err != nil {
		log.Fatalf("Error splitting data into blocks: %v", err)
	}

	// 对数据块生成冗余块
	err = enc.Encode(blocks)
	if err != nil {
		log.Fatalf("Error encoding blocks: %v", err)
	}

	// 将数据和冗余块拼接在一起
	var encodedData []byte
	for _, block := range blocks {
		encodedData = append(encodedData, block...)
	}

	// 模拟错误：丢弃某些数据块
	// 在此例中，我们丢弃了第二个数据块（索引为 1）
	blocks[1] = nil // 丢弃数据块

	// 解码：尝试恢复丢失的数据块
	// 如果丢失的数据量不超过冗余块数量，就能恢复
	err = enc.Reconstruct(blocks)
	if err != nil {
		log.Fatalf("Error decoding blocks: %v", err)
	}

	// 将解码后的数据重新组合成最终数据
	var decodedData []byte
	for _, block := range blocks[:dataShards] {
		decodedData = append(decodedData, block...)
	}

	// 打印结果
	fmt.Printf("Original Data: %s\n", data)
	fmt.Printf("Encoded Data (with redundancy): %x\n", encodedData)
	fmt.Printf("Decoded Data: %s\n", decodedData)
}
