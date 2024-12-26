package main

import (
	"Buyer/logger"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
)

const (
	EncryptedDataType = iota
	PublicKeyType
	StakeReturnType
	TxWithdrawType
)

type Message struct {
	Type    int    `json:"type"`
	Content string `json:"content"`
}

func sendMessageToSeller(conn net.Conn, message Message) {
	messageData, err := json.Marshal(message)
	if err != nil {
		logger.Error.Printf("Error marshalling message: %v", err)
		return
	}

	// 计算消息长度
	messageLength := len(messageData)
	lengthPrefix := make([]byte, 4) // 4字节长度前缀
	binary.BigEndian.PutUint32(lengthPrefix, uint32(messageLength))

	// 发送长度前缀
	_, err = conn.Write(lengthPrefix)
	if err != nil {
		logger.Error.Printf("Error sending message length:", err)
		return
	}

	// 发送实际的消息数据
	_, err = conn.Write(messageData)
	if err != nil {
		logger.Error.Printf("Error sending message:", err)
		return
	}
}

func receiveMessages(conn net.Conn) {
	for {
		// 读取长度前缀
		lengthPrefix := make([]byte, 4)
		_, err := conn.Read(lengthPrefix)
		if err != nil {
			logger.Error.Printf("Error reading message length: %v", err)
			return
		}
		messageLength := binary.BigEndian.Uint32(lengthPrefix)

		// 读取消息内容
		buffer := make([]byte, messageLength)
		_, err = conn.Read(buffer)
		if err != nil {
			logger.Error.Printf("Error reading message content: %v", err)
			return
		}

		var message Message
		err = json.Unmarshal(buffer, &message)
		if err != nil {
			logger.Error.Printf("Error unmarshaling message: %v", err)
			return
		}

		switch message.Type {
		case EncryptedDataType:
			logger.Info.Printf("Received encrypted data message from Seller")
			encryptedData, err = base64.StdEncoding.DecodeString(message.Content)
			if err != nil {
				logger.Error.Printf("Error decoding base64 encrypteddata: %v", err)
				panic(err)
			}
		case PublicKeyType:
			logger.Info.Printf("Received pk message from Seller")
			block, _ := pem.Decode([]byte(message.Content))
			if block == nil {
				logger.Error.Printf("failed to decode PEM block containing public key")
				panic("failed to decode PEM block containing public key")
			}
			pk, err = x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				logger.Error.Printf("failed to parse public key: %v", err)
				panic(err)
			}
		case StakeReturnType:
			logger.Info.Printf("Received stake return message from Seller")
		case TxWithdrawType:
			logger.Info.Printf("Received withdraw transaction message from Seller")
		default:
			fmt.Println("Unknown message type")
		}
	}
}
