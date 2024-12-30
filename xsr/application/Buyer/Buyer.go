package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"Buyer/logger"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"github.com/klauspost/reedsolomon"
	"google.golang.org/grpc/status"
)

const (
	channelName         = "mychannel"
	chaincodeName       = "xsr"
	logPath             = "../log/buyer"
	logLevel            = logger.TestLevel
	supervisionFilePath = "../supervision/database.txt"
	keySize             = 2048
)

var pk *rsa.PublicKey
var encryptedData []byte
var decryptedData []byte
var ch chan bool //用于防止还没收到消息就使用空的encryptedData

func main() {
	logger.SetOutput(logger.InfoLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-info-%s.log", logPath, "Buyer")))
	logger.SetOutput(logger.DebugLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-debug-%s.log", logPath, "Buyer")))
	logger.SetOutput(logger.WarnLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-warn-%s.log", logPath, "Buyer")))
	logger.SetOutput(logger.ErrorLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-error-%s.log", logPath, "Buyer")))
	logger.SetLevel(logger.Level(logLevel))
	ch = make(chan bool)
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	id := newIdentity()
	sign := newSign()

	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		logger.Error.Printf("gateway connect err %v\n", err)
	}
	defer gateway.Close()

	network := gateway.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// Context used for event listening
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for events emitted by subsequent transactions
	logger.Info.Printf("*** Start chaincode event listening\n")

	events, err := network.ChaincodeEvents(ctx, chaincodeName)
	if err != nil {
		logger.Error.Printf("failed to start chaincode event listening: %w", err)
		panic(err)
	}

	//tcp connection with seller
	serverAddr := "localhost:8080"
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		logger.Error.Printf("Error connecting to Seller: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Start a goroutine to receive messages from Seller
	go receiveMessages(conn)

	go func() {
		for event := range events {
			switch event.EventName {
			case "InitLedger":
				logger.Info.Printf("<-- Chaincode event received: %s\n", event.EventName)
				stake(contract, "account2", 100)
			case "CreateTransaction":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				moneylock, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, []byte("TRUE"), nil)
				if err != nil {
					logger.Error.Printf("failed to encrypt moneylock: %w", err)
					panic(err)
				}
				moneylockBase64 := base64.StdEncoding.EncodeToString(moneylock) //使用base64编码可以防止加密的数据在经过json序列化和类型转换时出现问题
				payforTx(contract, "account2", "tx1", 100, moneylockBase64)
			case "PayforTx":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				//Process to withdraw money from the account
				withdrawTx(contract, "account2", "tx1")
			case "WithdrawTx":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				logger.Info.Printf("Withdraw money successful")
			case "WithdrawTxUnilateral":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				logger.Info.Printf("Withdraw money successful")
			case "GetMoney":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				sk := getSecretKey(contract, "tx1")
				<-ch //阻塞等待
				logger.Info.Printf("Start RSA decryption")
				decryptedData, err = rsaDecryptChunks(sk, encryptedData)
				if err != nil {
					logger.Error.Printf("failed to decrypt data: %w", err)
					panic(err)
				}
				logger.Info.Printf("RSA decryption finish")
				//Start supervision process
				keyforsupervision := []byte("thisis32bitlongpassphrase!!!!!!!") // 32 字节密钥
				skMsg := Message{
					Type:    PublicKeyType,
					Content: string(keyforsupervision),
				}
				sendMessageToSeller(conn, skMsg)
				encryptedDataforSupervision, err := aesEncrypt(decryptedData, keyforsupervision)
				if err != nil {
					logger.Error.Printf("failed to encrypt data: %w", err)
					panic(err)
				}
				//Store the encrypted data in the database
				err = os.WriteFile(supervisionFilePath, []byte(encryptedDataforSupervision), 0644)
				if err != nil {
					logger.Error.Printf("failed to write encrypted data to file: %w", err)
					panic(err)
				}
				createsupervision(contract, "tx1", string(supervisionFilePath))
				reedsolomonEncode(keyforsupervision)
				logger.Info.Printf("normal situation finish")

				//logger.Info.Printf("Decrypted data: %s\n", string(decryptedData))
			default:
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
			}
		}
	}()

	for {

	}
}

func formatJSON(data []byte) string {
	var result bytes.Buffer
	if err := json.Indent(&result, data, "", "  "); err != nil {
		logger.Error.Printf("failed to parse JSON: %w", err)
		panic(err)
	}
	return result.String()
}

func stake(contract *client.Contract, id string, amount int) {
	logger.Info.Printf("--> Submit Transaction: Stake, owned by %s, amount = %d\n", id, amount)
	_, err := contract.SubmitTransaction("Stake", id, strconv.Itoa(amount))
	if err != nil {
		ErrorHandling(err)
		panic(fmt.Errorf("failed to submit transaction Stake: %v", err))
	}

	logger.Info.Printf("*** Transaction: Stake committed successfully")
}

func payforTx(contract *client.Contract, id string, txid string, money int, moneylock string) {
	logger.Info.Printf("--> Submit Transaction: PayforTx, txid %s\n", txid)
	_, err := contract.SubmitTransaction("PayforTx", id, txid, strconv.Itoa(money), moneylock)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction PayforTx: %v\n", err)
		return
	}

	logger.Info.Printf("*** Transaction: PayforTx committed successfully\n")
}

func getSecretKey(contract *client.Contract, txid string) *rsa.PrivateKey {
	logger.Info.Printf("--> Evaluate Transaction: GetSecretKey, txid %s\n", txid)
	evaluateResult, err := contract.EvaluateTransaction("GetSecretKey", txid)
	if err != nil {
		fmt.Printf("failed to evaluate transaction GetSecretKey: %v\n", err)
		return nil
	}
	block, _ := pem.Decode(evaluateResult)
	if block == nil {
		fmt.Printf("failed to decode PEM block containing the private key")
		return nil
	}
	sk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse private key: %v", err)
		return nil
	}

	logger.Info.Printf("*** Transaction: GetSecretKey evaluate successfully\n")
	return sk
}

func createsupervision(contract *client.Contract, txid string, key string) {
	logger.Info.Printf("--> Submit Transaction: CreateSupervision, txid %s\n", txid)
	_, err := contract.SubmitTransaction("CreateSupervision", txid, key)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction CreateSupervision: %v\n", err)
		return
	}

	logger.Info.Printf("*** Transaction: CreateSupervision committed successfully\n")
}

func withdrawTx(contract *client.Contract, id string, txid string) {
	logger.Info.Printf("--> Submit Transaction: WithdrawTx, txid %s\n", txid)
	_, err := contract.SubmitTransaction("WithdrawTx", id, txid)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction WithdrawTx: %v\n", err)
		return
	}

	logger.Info.Printf("*** Transaction: WithdrawTx committed successfully\n")
}

func withdrawTxUnilateral(contract *client.Contract, txid string) {
	logger.Info.Printf("--> Submit Transaction: WithdrawTxUnilateral, txid %s\n", txid)
	_, err := contract.SubmitTransaction("WithdrawTxUnilateral", txid)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction WithdrawTx: %v\n", err)
		return
	}

	logger.Info.Printf("*** Transaction: WithdrawTxUnilateral committed successfully\n")
}

// PKCS7 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
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

func reedsolomonEncode(data []byte) []byte {
	// 设置编码参数
	// 数据块大小
	dataShards := 8
	// 冗余块大小 (parity shards)
	parityShards := 4
	//totalShards := dataShards + parityShards

	// 创建 Reed-Solomon 编码器
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		logger.Error.Printf("Error creating Reed-Solomon encoder: %v", err)
	}

	// 编码
	// 创建一个新的切片，大小为 n 个数据块
	blocks, err := enc.Split(data)
	if err != nil {
		logger.Error.Printf("Error splitting data into blocks: %v", err)
	}

	// 对数据块生成冗余块
	err = enc.Encode(blocks)
	if err != nil {
		logger.Error.Printf("Error encoding blocks: %v", err)
	}

	// 将数据和冗余块拼接在一起
	var encodedData []byte
	for _, block := range blocks {
		encodedData = append(encodedData, block...)
	}
	return encodedData
}

// 分段解密
func rsaDecryptChunks(privKey *rsa.PrivateKey, encryptedData []byte) ([]byte, error) {
	var decryptedData []byte
	for i := 0; i < len(encryptedData); i += keySize / 8 {
		end := i + keySize/8
		if end > len(encryptedData) {
			end = len(encryptedData)
		}

		encryptedBlock := encryptedData[i:end]
		decryptedBlock, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedBlock, nil)
		if err != nil {
			return nil, err
		}

		// 拼接解密块
		decryptedData = append(decryptedData, decryptedBlock...)
	}
	return decryptedData, nil
}

func ErrorHandling(err error) {
	if err == nil {
		logger.Error.Printf("******** FAILED to return an error")
		panic("******** FAILED to return an error")
	}

	logger.Error.Printf("*** Successfully caught the error:")

	var endorseErr *client.EndorseError
	var submitErr *client.SubmitError
	var commitStatusErr *client.CommitStatusError
	var commitErr *client.CommitError

	if errors.As(err, &endorseErr) {
		logger.Error.Printf("Endorse error for transaction %s with gRPC status %v: %s\n", endorseErr.TransactionID, status.Code(endorseErr), endorseErr)
	} else if errors.As(err, &submitErr) {
		logger.Error.Printf("Submit error for transaction %s with gRPC status %v: %s\n", submitErr.TransactionID, status.Code(submitErr), submitErr)
	} else if errors.As(err, &commitStatusErr) {
		if errors.Is(err, context.DeadlineExceeded) {
			logger.Error.Printf("Timeout waiting for transaction %s commit status: %s", commitStatusErr.TransactionID, commitStatusErr)
		} else {
			logger.Error.Printf("Error obtaining commit status for transaction %s with gRPC status %v: %s\n", commitStatusErr.TransactionID, status.Code(commitStatusErr), commitStatusErr)
		}
	} else if errors.As(err, &commitErr) {
		logger.Error.Printf("Transaction %s failed to commit with status %d: %s\n", commitErr.TransactionID, int32(commitErr.Code), err)
	} else {
		logger.Error.Printf("Unexpected error type %T: %v\n", err, err)
		panic(fmt.Errorf("unexpected error type %T: %w", err, err))
	}

	// Any error that originates from a peer or orderer node external to the gateway will have its details
	// embedded within the gRPC status error. The following code shows how to extract that.
	statusErr := status.Convert(err)

	details := statusErr.Details()
	if len(details) > 0 {
		logger.Error.Printf("Error Details:")

		for _, detail := range details {
			switch detail := detail.(type) {
			case *gateway.ErrorDetail:
				logger.Error.Printf("- address: %s; mspId: %s; message: %s\n", detail.Address, detail.MspId, detail.Message)
			}
		}
	}
}
