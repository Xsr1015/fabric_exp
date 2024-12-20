package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	// Buyer 连接 Seller 的 TCP 服务器（127.0.0.1:8080）
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal("Error connecting to server:", err)
	}
	defer conn.Close()

	// 向 Seller 发送消息
	message := "Hello from Buyer"
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Fatal("Error sending message to server:", err)
	}
	fmt.Println("Sent to Seller:", message)

	// 接收 Seller 的响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			fmt.Println("Server closed connection")
		} else {
			log.Fatal("Error reading from server:", err)
		}
	}
	fmt.Printf("Received from Seller: %s\n", string(buf[:n]))
}
