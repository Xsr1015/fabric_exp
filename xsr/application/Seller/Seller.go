package main

import (
	"Seller/logger"
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
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"github.com/klauspost/reedsolomon"
	"google.golang.org/grpc/status"
)

const (
	channelName   = "mychannel"
	chaincodeName = "xsr"
	logPath       = "../log/seller"
	logLevel      = logger.TestLevel
	dataSize      = 1024 //bytes
	keySize       = 2048 //bits
	maxBlockSize  = 190  //最大可以加密的数据块大小
)

var sk *rsa.PrivateKey
var pk *rsa.PublicKey
var keyforsupervision []byte

func main() {
	//log configuration
	logger.SetOutput(logger.InfoLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-info-%s.log", logPath, "Seller")))
	logger.SetOutput(logger.DebugLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-debug-%s.log", logPath, "Seller")))
	logger.SetOutput(logger.WarnLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-warn-%s.log", logPath, "Seller")))
	logger.SetOutput(logger.ErrorLevel, logger.NewFileWriter(fmt.Sprintf("%s/node-error-%s.log", logPath, "Seller")))
	logger.SetLevel(logger.Level(logLevel))

	data, err := randomString(dataSize)
	if err != nil {
		logger.Error.Printf("failed to generate random data: %w", err)
		panic(err)
	}

	//connect to gateway
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
		logger.Error.Printf("failed to connect to gateway: %v", err)
		panic(err)
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

	// tcp connection with buyer
	listen, err := net.Listen("tcp", ":8080")
	if err != nil {
		logger.Error.Printf("Error starting server: %v", err)
		os.Exit(1)
	}
	defer listen.Close()
	conn, err := listen.Accept() //wait for buyer to connect
	if err != nil {
		logger.Error.Printf("Error accepting connection: %v", err)
		panic(err)
	}
	go receiveMessages(conn)

	go func() {
		for event := range events {
			switch event.EventName {
			case "InitLedger":
				logger.Info.Printf("<-- Chaincode event received: %s\n", event.EventName)
				stake(contract, "account1", 100)
			case "account2Stake":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)

				//generate key for transaction
				logger.Info.Printf("data size: %d bytes\n", len(data))
				logger.Info.Printf("Start to encrypt data\n")
				sk, err = rsa.GenerateKey(rand.Reader, keySize)
				if err != nil {
					logger.Error.Printf("failed to generatekey: %w", err)
					panic(err)
				}
				pk = &sk.PublicKey
				pkBytes := x509.MarshalPKCS1PublicKey(pk)
				pkPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkBytes})
				encryptedData, err := rsaEncryptChunks(pk, data)
				if err != nil {
					logger.Error.Printf("failed to encrypt: %w", err)
					panic(err)
				}
				encryptedDataBase64 := base64.StdEncoding.EncodeToString(encryptedData)
				if strings.Contains(encryptedDataBase64, "\x00") {
					panic("Message contains null byte (\\x00)")
				}
				datahash := sha256.New()
				datahash.Write(data)
				datahashbytes := datahash.Sum(nil)
				logger.Info.Printf("data encrypted\n")
				encrypteddatamsg := Message{
					Type:    EncryptedDataType,
					Content: encryptedDataBase64,
				}
				pkdatamsg := Message{
					Type:    PublicKeyType,
					Content: string(pkPem),
				}
				sendMessageToBuyer(conn, pkdatamsg)
				sendMessageToBuyer(conn, encrypteddatamsg)

				createTransaction(contract, "tx1", "account1", "account2", string(datahashbytes))
			case "PayforTx":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				//getMoney(contract, "account1", "tx1", sk)
			case "account2WithdrawTx":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				withdrawTx(contract, "account1", "tx1")
			case "WithdrawTx":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				logger.Info.Printf("Withdraw money successful")
			case "WithdrawTxUnilateral":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				logger.Info.Printf("Withdraw money successful")
			case "CreateSupervision":
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
				datapath := readSupervision(contract, "tx1-supervision")
				if datapath == "" {
					logger.Error.Printf("failed to read supervision")
					panic("failed to read supervision")
				}
				encryptedDataforSupervision, err := os.ReadFile(datapath)
				if err != nil {
					logger.Error.Printf("failed to read data from file: %v", err)
					panic(err)
				}
				decryptedDataforSupervision, err := aesDecrypt(string(encryptedDataforSupervision), keyforsupervision)
				if err != nil {
					logger.Error.Printf("failed to decrypt data for supervision: %v", err)
					panic(err)
				}
				if decryptedDataforSupervision != string(data) {
					logger.Error.Printf("data not match!")
					panic("data not match")
				}
				reedsolomonEncode(keyforsupervision) //reed-solomon encode the key for supervision
				logger.Info.Printf("normal situation finish")
			default:
				asset := formatJSON(event.Payload)
				logger.Info.Printf("<-- Chaincode event received: %s - %s\n", event.EventName, asset)
			}
		}
	}()

	deleteAllAssets(contract)
	initLedger(contract)

	for {
	}
	// Replay events from the block containing the first transaction
	//replayChaincodeEvents(ctx, network, firstBlockNumber)
}

func formatJSON(data []byte) string {
	var result bytes.Buffer
	if err := json.Indent(&result, data, "", "  "); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return result.String()
}

func randomString(size int) ([]byte, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return b, nil
}

func initLedger(contract *client.Contract) {
	fmt.Printf("--> Submit Transaction: InitLedger, function creates the initial set of accounts on the ledger \n")

	_, err := contract.SubmitTransaction("InitLedger")
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction InitLedger: %w", err))
	}

	fmt.Printf("*** Transaction: InitLedger committed successfully\n")
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

func returnStake(contract *client.Contract, id string) {
	fmt.Printf("--> Submit Transaction: ReturnStake, stake owned by %s\n", id)
	_, err := contract.SubmitTransaction("ReturnStake", id)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to ReturnStake: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: ReturnStake committed successfully\n")
}

func confirmReturnStake(contract *client.Contract, id string) {
	fmt.Printf("--> Submit Transaction: ConfirmReturnStake, stake owned by %s\n", id)
	_, err := contract.SubmitTransaction("ConfirmReturnStake", id)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to ConfirmReturnStake: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: ConfirmReturnStake committed successfully\n")
}

func createTransaction(contract *client.Contract, txid string, seller string, buyer string, datahash string) {
	logger.Info.Printf("--> Submit Transaction: CreateTransaction, txid %s\n", txid)
	_, err := contract.SubmitTransaction("CreateTransaction", txid, seller, buyer, datahash)
	if err != nil {
		ErrorHandling(err)
		panic(fmt.Errorf("failed to submit transaction CreateTransaction: %v", err))
	}

	logger.Info.Printf("*** Transaction: CreateTransaction committed successfully\n")
}

func getMoney(contract *client.Contract, id string, txid string, secretkey *rsa.PrivateKey) {
	privBytes := x509.MarshalPKCS1PrivateKey(secretkey)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	logger.Info.Printf("--> Submit Transaction: GetMoney, txid %s\n", txid)
	_, err := contract.SubmitTransaction("GetMoney", id, txid, string(privPem))
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction GetMoney: %v\n", err)
		return
	}

	logger.Info.Printf("*** Transaction: GetMoney committed successfully\n")
}

func deleteAllAssets(contract *client.Contract) {
	fmt.Printf("--> Submit Transaction: DeleteAllAssets\n")
	_, err := contract.SubmitTransaction("DeleteAllAssets")
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction DeleteAllAssets: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: DeleteAllAssets committed successfully\n")
}

func readSupervision(contract *client.Contract, txid string) string {
	logger.Info.Printf("--> Evaluate Transaction: ReadSupervision, txid %s\n", txid)
	result, err := contract.EvaluateTransaction("ReadSupervision", txid)
	if err != nil {
		logger.Error.Printf("failed to evaluate transaction ReadSupervision: %v\n", err)
		return ""
	}
	logger.Info.Printf("*** Result: %s\n", result)
	return string(result)
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

// 分段加密
func rsaEncryptChunks(pubKey *rsa.PublicKey, data []byte) ([]byte, error) {
	// 切割数据为多个块
	var encryptedData []byte
	for i := 0; i < len(data); i += maxBlockSize {
		end := i + maxBlockSize
		if end > len(data) {
			end = len(data)
		}

		block := data[i:end]
		encryptedBlock, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, block, nil)
		if err != nil {
			return nil, err
		}

		// 拼接加密块
		encryptedData = append(encryptedData, encryptedBlock...)
	}
	return encryptedData, nil
}

func replayChaincodeEvents(ctx context.Context, network *client.Network, startBlock uint64) {
	fmt.Println("\n*** Start chaincode event replay")

	events, err := network.ChaincodeEvents(ctx, chaincodeName, client.WithStartBlock(startBlock))
	if err != nil {
		panic(fmt.Errorf("failed to start chaincode event listening: %w", err))
	}

	for {
		select {
		case <-time.After(10 * time.Second):
			panic(errors.New("timeout waiting for event replay"))

		case event := <-events:
			asset := formatJSON(event.Payload)
			fmt.Printf("\n<-- Chaincode event replayed: %s - %s\n", event.EventName, asset)

			if event.EventName == "GetMoney" {
				// Reached the last submitted transaction so return to stop listening for events
				return
			}
		}
	}
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
