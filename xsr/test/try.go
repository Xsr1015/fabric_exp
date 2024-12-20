package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func main() {
	//generate key for transaction
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Errorf("failed to generatekey: %w", err))
	}
	pk := &sk.PublicKey
	moneylock, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, []byte("TRUE"), nil)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt moneylock: %w", err))
	}
	moneylockBase64 := base64.StdEncoding.EncodeToString(moneylock) //使用base64编码可以防止加密的数据在经过json序列化和类型转换时出现问题
	moneylockjson, _ := json.Marshal(moneylockBase64)
	json.Unmarshal(moneylockjson, &moneylockBase64)
	decodedMoneylock, err := base64.StdEncoding.DecodeString(moneylockBase64)
	if err != nil {
		panic(fmt.Errorf("failed to decode moneylock: %v", err))
	}
	// moneylockstr := string(moneylock)
	// moneylockjson, _ := json.Marshal(moneylockstr)
	// json.Unmarshal(moneylockjson, &moneylockstr)
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, sk, decodedMoneylock, nil)
	if err != nil {
		panic(fmt.Errorf("failed to decrypt data: %w", err))
	}
	fmt.Print(string(decryptedData))
	if string(decryptedData) == "TRUE" {
		fmt.Printf("test approved!")
	}
}
