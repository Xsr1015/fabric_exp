package main

import (
	"Seller/logger"
	"encoding/binary"
	"encoding/json"
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
			logger.Info.Printf("Received encrypted data message from Buyer")
		case PublicKeyType:
			logger.Info.Printf("Received public key message from Buyer")
		case StakeReturnType:
			logger.Info.Printf("Received stake return message from Buyer")
		case TxWithdrawType:
			logger.Info.Printf("Received withdraw transaction message from Buyer")

		default:
			logger.Info.Printf("Unknown message type")
		}
	}
}

func sendMessageToBuyer(conn net.Conn, message Message) {
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
