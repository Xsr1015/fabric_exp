package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/status"
)

const (
	channelName   = "mychannel"
	chaincodeName = "xsr"
)

func main() {
	//generate key for transaction
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Errorf("failed to generatekey: %w", err))
	}
	pk := &sk.PublicKey
	data := []byte("这是测试数据")
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, data, nil)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt: %w", err))
	}
	moneylock, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, []byte("TRUE"), nil)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt moneylock: %w", err))
	}
	moneylockBase64 := base64.StdEncoding.EncodeToString(moneylock)
	datahash := sha256.New()
	datahash.Write(data)
	datahashbytes := datahash.Sum(nil)
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
		panic(err)
	}
	defer gateway.Close()

	network := gateway.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// Context used for event listening
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for events emitted by subsequent transactions
	startChaincodeEventListening(ctx, network)
	deleteAllAssets(contract)
	time.Sleep(1 * time.Second)
	initLedger(contract)
	time.Sleep(1 * time.Second)
	firstBlockNumber := stake(contract, "account1", 100)
	time.Sleep(1 * time.Second)
	returnStake(contract, "account1")
	time.Sleep(1 * time.Second)
	confirmReturnStake(contract, "account1")
	time.Sleep(1 * time.Second)
	createTransaction(contract, "tx1", "account1", "account2", string(datahashbytes))
	time.Sleep(1 * time.Second)
	payforTx(contract, "account2", "tx1", 100, moneylockBase64)
	time.Sleep(1 * time.Second)
	getMoney(contract, "account1", "tx1", sk)
	time.Sleep(1 * time.Second)
	skfromtx := getSecretKey(contract, "tx1")
	if skfromtx == nil {
		panic("failed to get sk")
	}
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, skfromtx, encryptedData, nil)
	if err != nil {
		panic(fmt.Errorf("failed to decrypt data: %w", err))
	}
	fmt.Print(string(decryptedData))
	if string(decryptedData) == string(encryptedData) {
		fmt.Printf("test approved!")
	}
	// Replay events from the block containing the first transaction
	replayChaincodeEvents(ctx, network, firstBlockNumber)
}

func startChaincodeEventListening(ctx context.Context, network *client.Network) {
	fmt.Println("\n*** Start chaincode event listening")

	events, err := network.ChaincodeEvents(ctx, chaincodeName)
	if err != nil {
		panic(fmt.Errorf("failed to start chaincode event listening: %w", err))
	}

	go func() {
		for event := range events {
			asset := formatJSON(event.Payload)
			fmt.Printf("\n<-- Chaincode event received: %s - %s\n", event.EventName, asset)
		}
	}()
}

func formatJSON(data []byte) string {
	var result bytes.Buffer
	if err := json.Indent(&result, data, "", "  "); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return result.String()
}

func initLedger(contract *client.Contract) {
	fmt.Printf("\n--> Submit Transaction: InitLedger, function creates the initial set of accounts on the ledger \n")

	_, err := contract.SubmitTransaction("InitLedger")
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction InitLedger: %w", err))
	}

	fmt.Printf("*** Transaction: InitLedger committed successfully\n")
}

func stake(contract *client.Contract, id string, amount int) uint64 {
	fmt.Printf("\n--> Submit Transaction: Stake, owned by %s, amount = %d\n", id, amount)
	_, commit, err := contract.SubmitAsync("Stake", client.WithArguments(id, strconv.Itoa(amount)))
	if err != nil {
		ErrorHandling(err)
		panic(fmt.Errorf("failed to submit transaction Stake: %v", err))
	}

	status, err := commit.Status()
	if err != nil {
		panic(fmt.Errorf("failed to get transaction commit status: %v", err))
	}

	if !status.Successful {
		panic(fmt.Errorf("failed to commit transaction with status code %v", status.Code))
	}

	fmt.Println("\n*** Transaction: Stake committed successfully")

	return status.BlockNumber
}

func returnStake(contract *client.Contract, id string) {
	fmt.Printf("\n--> Submit Transaction: ReturnStake, stake owned by %s\n", id)
	_, err := contract.SubmitTransaction("ReturnStake", id)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to ReturnStake: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: ReturnStake committed successfully\n")
}

func confirmReturnStake(contract *client.Contract, id string) {
	fmt.Printf("\n--> Submit Transaction: ConfirmReturnStake, stake owned by %s\n", id)
	_, err := contract.SubmitTransaction("ConfirmReturnStake", id)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to ConfirmReturnStake: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: ConfirmReturnStake committed successfully\n")
}

func createTransaction(contract *client.Contract, txid string, seller string, buyer string, datahash string) {
	fmt.Printf("\n--> Submit Transaction: CreateTransaction, txid %s\n", txid)
	_, err := contract.SubmitTransaction("CreateTransaction", txid, seller, buyer, datahash)
	if err != nil {
		ErrorHandling(err)
		panic(fmt.Errorf("failed to submit transaction CreateTransaction: %v", err))
	}

	fmt.Printf("*** Transaction: CreateTransaction committed successfully\n")
}

func payforTx(contract *client.Contract, id string, txid string, money int, moneylock string) {
	fmt.Printf("\n--> Submit Transaction: PayforTx, txid %s\n", txid)
	_, err := contract.SubmitTransaction("PayforTx", id, txid, strconv.Itoa(money), moneylock)
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction PayforTx: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: PayforTx committed successfully\n")
}

func getMoney(contract *client.Contract, id string, txid string, secretkey *rsa.PrivateKey) {
	privBytes := x509.MarshalPKCS1PrivateKey(secretkey)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	fmt.Printf("\n--> Submit Transaction: GetMoney, txid %s\n", txid)
	_, err := contract.SubmitTransaction("GetMoney", id, txid, string(privPem))
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction GetMoney: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: GetMoney committed successfully\n")
}

func getSecretKey(contract *client.Contract, txid string) *rsa.PrivateKey {
	fmt.Printf("\n--> Evaluate Transaction: GetSecretKey, txid %s\n", txid)
	evaluateResult, err := contract.EvaluateTransaction("GetSecretKey", txid)
	if err != nil {
		fmt.Printf("failed to evaluate transaction GetSecretKey: %v\n", err)
		return nil
	}
	block, _ := pem.Decode([]byte(evaluateResult))
	if block == nil {
		fmt.Printf("failed to decode PEM block containing the private key")
		return nil
	}
	sk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse private key: %v", err)
		return nil
	}

	fmt.Printf("*** Transaction: GetSecretKey evaluate successfully\n")
	return sk
}

func deleteAllAssets(contract *client.Contract) {
	fmt.Printf("\n--> Submit Transaction: DeleteAllAssets\n")
	_, err := contract.SubmitTransaction("DeleteAllAssets")
	if err != nil {
		ErrorHandling(err)
		fmt.Printf("failed to submit transaction DeleteAllAssets: %v\n", err)
		return
	}

	fmt.Printf("*** Transaction: DeleteAllAssets committed successfully\n")
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
		panic("******** FAILED to return an error")
	}

	fmt.Println("*** Successfully caught the error:")

	var endorseErr *client.EndorseError
	var submitErr *client.SubmitError
	var commitStatusErr *client.CommitStatusError
	var commitErr *client.CommitError

	if errors.As(err, &endorseErr) {
		fmt.Printf("Endorse error for transaction %s with gRPC status %v: %s\n", endorseErr.TransactionID, status.Code(endorseErr), endorseErr)
	} else if errors.As(err, &submitErr) {
		fmt.Printf("Submit error for transaction %s with gRPC status %v: %s\n", submitErr.TransactionID, status.Code(submitErr), submitErr)
	} else if errors.As(err, &commitStatusErr) {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Printf("Timeout waiting for transaction %s commit status: %s", commitStatusErr.TransactionID, commitStatusErr)
		} else {
			fmt.Printf("Error obtaining commit status for transaction %s with gRPC status %v: %s\n", commitStatusErr.TransactionID, status.Code(commitStatusErr), commitStatusErr)
		}
	} else if errors.As(err, &commitErr) {
		fmt.Printf("Transaction %s failed to commit with status %d: %s\n", commitErr.TransactionID, int32(commitErr.Code), err)
	} else {
		panic(fmt.Errorf("unexpected error type %T: %w", err, err))
	}

	// Any error that originates from a peer or orderer node external to the gateway will have its details
	// embedded within the gRPC status error. The following code shows how to extract that.
	statusErr := status.Convert(err)

	details := statusErr.Details()
	if len(details) > 0 {
		fmt.Println("Error Details:")

		for _, detail := range details {
			switch detail := detail.(type) {
			case *gateway.ErrorDetail:
				fmt.Printf("- address: %s; mspId: %s; message: %s\n", detail.Address, detail.MspId, detail.Message)
			}
		}
	}
}
