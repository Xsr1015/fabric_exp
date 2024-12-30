package chaincode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// SmartContract provides functions for managing an Account
type SmartContract struct {
	contractapi.Contract
}

type Account struct {
	Amount   int    `json:"Amount"`
	ID       string `json:"ID"`
	Mortgage int    `json:"Mortgage"`
	Owner    string `json:"Owner"`
}

type Stake struct {
	Staker   string `json:"staker"`
	Amount   int    `json:"amount"`
	StakedAt int64  `json:"stakedAt"`
	ReturnAt int64  `json:"returnAt"`
	Returned bool   `json:"returned"`
	Flag1    bool   `json:"flag1"` //Whether Staker wants to return the stake
	Flag2    bool   `json:"flag2"` //Whether the other one wants to let the Staker to return the stake
}

type Transaction struct {
	TXID      string `json:"txid"`
	Seller    string `json:"seller"`
	Buyer     string `json:"buyer"`
	DataHash  string `json:"datahash"`
	Money     int    `json:"money"`
	SecretKey string `json:"secretkey"` //pem encoded string of the private key
	MoneyLock string `json:"moneylock"` //An encrypted string of the "TRUE"
	Flag1     bool   `json:"flag1"`     //Whether Seller wants to withdraw the tx
	Flag2     bool   `json:"flag2"`     //Whether Buyer wants to withdraw the tx
	Finished  bool   `json:"finished"`  //Whether the tx is finished
}

type SupervisionTx struct {
	SID  string `json:"id"`
	TXID string `json:"txid"`
	Key  string `json:"key"`
}

// InitLedger adds a base set of accounts to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	accounts := []Account{
		{ID: "account1", Owner: "Seller", Amount: 100000, Mortgage: 0},
		{ID: "account2", Owner: "Buyer", Amount: 100000, Mortgage: 0},
	}

	for _, account := range accounts {
		accountJSON, err := json.Marshal(account)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(account.ID, accountJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	ctx.GetStub().SetEvent("InitLedger", nil)
	return nil
}

// CreateAccount issues a new account to the world state with given details.
func (s *SmartContract) CreateAccount(ctx contractapi.TransactionContextInterface, id string, owner string, amount int, mortgage int) error {
	exists, err := s.AccountExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the account %s already exists", id)
	}

	account := Account{
		ID:       id,
		Amount:   amount,
		Mortgage: mortgage,
		Owner:    owner,
	}
	accountJSON, err := json.Marshal(account)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, accountJSON)
}

// ReadAccount returns the account stored in the world state with given id.
func (s *SmartContract) ReadAccount(ctx contractapi.TransactionContextInterface, id string) (*Account, error) {
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSON == nil {
		return nil, fmt.Errorf("the account %s does not exist", id)
	}

	var account Account
	err = json.Unmarshal(accountJSON, &account)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

// UpdateAccount updates an existing account in the world state with provided parameters.
func (s *SmartContract) UpdateAccount(ctx contractapi.TransactionContextInterface, id string, owner string, amount int, mortgage int) error {
	exists, err := s.AccountExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the account %s does not exist", id)
	}

	// overwriting original account with new account
	account := Account{
		ID:       id,
		Amount:   amount,
		Mortgage: mortgage,
		Owner:    owner,
	}
	accountJSON, err := json.Marshal(account)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, accountJSON)
}

// DeleteAccount deletes an given account from the world state.
func (s *SmartContract) DeleteAccount(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.AccountExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the account %s does not exist", id)
	}

	return ctx.GetStub().DelState(id)
}

// AccountExists returns true when account with given ID exists in world state
func (s *SmartContract) AccountExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return accountJSON != nil, nil
}

// GetAllAccounts returns all accounts found in world state
func (s *SmartContract) GetAllAccounts(ctx contractapi.TransactionContextInterface) ([]*Account, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all accounts in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var accounts []*Account
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var account Account
		err = json.Unmarshal(queryResponse.Value, &account)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, &account)
	}

	return accounts, nil
}

// Deposit some token before trading
func (s *SmartContract) Stake(ctx contractapi.TransactionContextInterface, id string, amount int) error {
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSON == nil {
		return fmt.Errorf("the account %s does not exist", id)
	}
	var account Account
	err = json.Unmarshal(accountJSON, &account)
	if err != nil {
		return err
	}
	if account.Amount < amount {
		return fmt.Errorf("not enough money")
	}

	currentTime := time.Now().Unix()

	// 设定返还时间为质押时间 + 一定的延迟
	returnAt := currentTime + 60*60 // 1 hour

	stake := Stake{
		Staker:   id + "-stake",
		Amount:   amount,
		StakedAt: currentTime,
		ReturnAt: returnAt,
		Returned: false,
		Flag1:    false,
		Flag2:    false,
	}

	stakeJSON, err := json.Marshal(stake)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(stake.Staker, stakeJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	account.Amount -= amount
	account.Mortgage += amount
	accountJSON, err = json.Marshal(account)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id, accountJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	ctx.GetStub().SetEvent(id+"Stake", stakeJSON)
	return nil
}

// ReturnStake try to return the token deposited
func (s *SmartContract) ReturnStake(ctx contractapi.TransactionContextInterface, id string) error {
	stakeJSON, err := ctx.GetStub().GetState(id + "-stake")
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if stakeJSON == nil {
		return fmt.Errorf("the stake %s does not exist", id)
	}

	var stake Stake
	err = json.Unmarshal(stakeJSON, &stake)
	if err != nil {
		return err
	}
	stake.Flag1 = true
	if stake.Returned {
		return fmt.Errorf("Stake already returned")
	}
	// 检查是否可以返还
	currentTime := time.Now().Unix()
	if currentTime < stake.ReturnAt && !stake.Flag2 {
		stakeJSON, err = json.Marshal(stake) //to update Flag1
		if err != nil {
			return err
		}
		err = ctx.GetStub().PutState(id+"-stake", stakeJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		ctx.GetStub().SetEvent(id+"ReturnStake", stakeJSON)
		return nil
	}
	// 更新状态
	stake.Returned = true
	stakeJSON, err = json.Marshal(stake)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id+"-stake", stakeJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSON == nil {
		return fmt.Errorf("the account %s does not exist", id)
	}

	var account Account
	err = json.Unmarshal(accountJSON, &account)
	if err != nil {
		return err
	}
	account.Mortgage -= stake.Amount
	account.Amount += stake.Amount
	accountJSON, err = json.Marshal(account)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id, accountJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	ctx.GetStub().SetEvent("ReturnStake", stakeJSON)
	return nil
}

// ConfirmReturnStake confirm the return of the token
func (s *SmartContract) ConfirmReturnStake(ctx contractapi.TransactionContextInterface, id string) error {
	stakeJSON, err := ctx.GetStub().GetState(id + "-stake")
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if stakeJSON == nil {
		return fmt.Errorf("the stake %s does not exist", id)
	}

	var stake Stake
	err = json.Unmarshal(stakeJSON, &stake)
	if err != nil {
		return err
	}
	if stake.Returned {
		return fmt.Errorf("Stake already returned")
	}
	stake.Flag2 = true
	if !stake.Flag1 {
		stakeJSON, err = json.Marshal(stake) //to update Flag2
		if err != nil {
			return err
		}
		err = ctx.GetStub().PutState(id+"-stake", stakeJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		ctx.GetStub().SetEvent(id+"ConfirmReturnStake", stakeJSON)
		return nil
	}
	// 更新状态
	stake.Returned = true
	stakeJSON, err = json.Marshal(stake)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id+"-stake", stakeJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSON == nil {
		return fmt.Errorf("the account %s does not exist", id)
	}

	var account Account
	err = json.Unmarshal(accountJSON, &account)
	if err != nil {
		return err
	}
	account.Mortgage -= stake.Amount
	account.Amount += stake.Amount
	accountJSON, err = json.Marshal(account)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id, accountJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	ctx.GetStub().SetEvent("ConfirmReturnStake", stakeJSON)
	return nil
}

// CreateTransaction issues a new transaction to the world state
func (s *SmartContract) CreateTransaction(ctx contractapi.TransactionContextInterface, txid string, seller string, buyer string, datahash string) error {
	txjson, err := ctx.GetStub().GetState(txid)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if txjson != nil {
		return fmt.Errorf("the transaction %s already exists", txid)
	}
	tx := Transaction{
		TXID:      txid,
		Seller:    seller,
		Buyer:     buyer,
		DataHash:  datahash,
		Money:     0,
		SecretKey: "",
		MoneyLock: "",
		Flag1:     false,
		Flag2:     false,
		Finished:  false,
	}
	txjson, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx err. %v", err)
	}
	ctx.GetStub().SetEvent("CreateTransaction", txjson)
	return ctx.GetStub().PutState(txid, txjson)
}

// PayforTx pay for a transaction
func (s *SmartContract) PayforTx(ctx contractapi.TransactionContextInterface, id string, txid string, money int, moneylock string) error {
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSON == nil {
		return fmt.Errorf("the account %s does not exist", id)
	}

	txjson, err := ctx.GetStub().GetState(txid)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if txjson == nil {
		return fmt.Errorf("the transaction %s does not exist", txid)
	}

	var account Account
	err = json.Unmarshal(accountJSON, &account)
	if err != nil {
		return fmt.Errorf("unmarshal account err. %v", err)
	}
	if account.Amount < money {
		return fmt.Errorf("not enough money")
	}
	account.Amount -= money
	accountJSON, err = json.Marshal(account)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id, accountJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	var tx Transaction
	err = json.Unmarshal(txjson, &tx)
	if err != nil {
		return fmt.Errorf("unmarshal tx err. %v", err)
	}
	tx.Money += money
	tx.MoneyLock = moneylock
	txjson, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx err. %v", err)
	}
	err = ctx.GetStub().PutState(txid, txjson)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	ctx.GetStub().SetEvent("PayforTx", txjson)
	return nil
}

// Seller try to get the money use the secret key
func (s *SmartContract) GetMoney(ctx contractapi.TransactionContextInterface, id string, txid string, secretkey string) error {
	accountJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSON == nil {
		return fmt.Errorf("the account %s does not exist", id)
	}

	txjson, err := ctx.GetStub().GetState(txid)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if txjson == nil {
		return fmt.Errorf("the transaction %s does not exist", txid)
	}
	var tx Transaction
	err = json.Unmarshal(txjson, &tx)
	if err != nil {
		return fmt.Errorf("unmarshal tx err. %v", err)
	}

	if tx.Finished {
		return fmt.Errorf("the transaction is finished")
	}

	block, _ := pem.Decode([]byte(secretkey))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing the private key")
	}
	sk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}
	moneylock, err := base64.StdEncoding.DecodeString(tx.MoneyLock)
	if err != nil {
		return fmt.Errorf("failed to decode moneylock: %v", err)
	}
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, sk, moneylock, nil)
	if err != nil {
		return fmt.Errorf("decryptoaep err. %v", err)
	}
	if string(decryptedData) != "TRUE" {
		return fmt.Errorf("the secret key is wrong")
	}
	tx.SecretKey = secretkey
	tx.Money = 0
	tx.Finished = true
	var account Account
	err = json.Unmarshal(accountJSON, &account)
	if err != nil {
		return fmt.Errorf("unmarshal account err. %v", err)
	}
	account.Amount += tx.Money
	txjson, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx err. %v", err)
	}
	err = ctx.GetStub().PutState(txid, txjson)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	accountJSON, err = json.Marshal(account)
	if err != nil {
		return fmt.Errorf("marshal account err. %v", err)
	}
	err = ctx.GetStub().PutState(id, accountJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	ctx.GetStub().SetEvent("GetMoney", txjson)
	return nil
}

// GetSecretKey get the secret key of the transaction
func (s *SmartContract) GetSecretKey(ctx contractapi.TransactionContextInterface, txid string) (string, error) {
	txjson, err := ctx.GetStub().GetState(txid)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %v", err)
	}
	if txjson == nil {
		return "", fmt.Errorf("the transaction %s does not exist", txid)
	}
	var tx Transaction
	err = json.Unmarshal(txjson, &tx)
	if err != nil {
		return "", fmt.Errorf("unmarshal tx err. %v", err)
	}
	if tx.SecretKey == "" {
		return "", fmt.Errorf("the secret key is not set")
	}
	return tx.SecretKey, nil
}

// WithdrawTx withdraw the transaction if both seller and buyer agree
func (s *SmartContract) WithdrawTx(ctx contractapi.TransactionContextInterface, id string, txid string) error {
	txjson, err := ctx.GetStub().GetState(txid)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if txjson == nil {
		return fmt.Errorf("the transaction %s does not exist", txid)
	}
	var tx Transaction
	err = json.Unmarshal(txjson, &tx)
	if err != nil {
		return fmt.Errorf("unmarshal tx err. %v", err)
	}
	if tx.Finished {
		return fmt.Errorf("the transaction is finished")
	}
	accountJSONs, err := ctx.GetStub().GetState(tx.Seller)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSONs == nil {
		return fmt.Errorf("the account %s does not exist", tx.Seller)
	}
	accountJSONb, err := ctx.GetStub().GetState(tx.Buyer)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSONb == nil {
		return fmt.Errorf("the account %s does not exist", tx.Buyer)
	}

	if tx.Seller == id {
		tx.Flag1 = true
	} else if tx.Buyer == id {
		tx.Flag2 = true
	}
	if tx.Flag1 && tx.Flag2 {
		tx.Finished = true
		// give the money back to the buyer
		var accountb Account
		err = json.Unmarshal(accountJSONb, &accountb)
		if err != nil {
			return fmt.Errorf("unmarshal account err. %v", err)
		}
		accountb.Amount += tx.Money
		tx.Money = 0
		//return the stake of both seller and buyer
		stakeJSONs, err := ctx.GetStub().GetState(tx.Seller + "-stake")
		if err != nil {
			return fmt.Errorf("failed to read from world state: %v", err)
		}
		stakeJSONb, err := ctx.GetStub().GetState(tx.Buyer + "-stake")
		if err != nil {
			return fmt.Errorf("failed to read from world state: %v", err)
		}
		var stakes Stake
		err = json.Unmarshal(stakeJSONs, &stakes)
		if err != nil {
			return fmt.Errorf("unmarshal stake err. %v", err)
		}
		var stakeb Stake
		err = json.Unmarshal(stakeJSONb, &stakeb)
		if err != nil {
			return fmt.Errorf("unmarshal stake err. %v", err)
		}
		var accounts Account
		err = json.Unmarshal(accountJSONs, &accounts)
		if err != nil {
			return fmt.Errorf("unmarshal account err. %v", err)
		}
		stakes.Returned = true
		stakeb.Returned = true
		accounts.Amount += stakes.Amount
		accounts.Mortgage -= stakes.Amount
		accountb.Amount += stakeb.Amount
		accountb.Mortgage -= stakeb.Amount
		stakeJSONs, err = json.Marshal(stakes)
		if err != nil {
			return fmt.Errorf("marshal stake err. %v", err)
		}
		stakeJSONb, err = json.Marshal(stakeb)
		if err != nil {
			return fmt.Errorf("marshal stake err. %v", err)
		}
		err = ctx.GetStub().PutState(tx.Seller+"-stake", stakeJSONs)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		err = ctx.GetStub().PutState(tx.Buyer+"-stake", stakeJSONb)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		txjson, err = json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("marshal tx err. %v", err)
		}
		err = ctx.GetStub().PutState(txid, txjson)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		accountJSONs, err = json.Marshal(accounts)
		if err != nil {
			return fmt.Errorf("marshal account err. %v", err)
		}
		accountJSONb, err = json.Marshal(accountb)
		if err != nil {
			return fmt.Errorf("marshal account err. %v", err)
		}
		err = ctx.GetStub().PutState(tx.Buyer, accountJSONb)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		err = ctx.GetStub().PutState(tx.Seller, accountJSONs)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		ctx.GetStub().SetEvent("WithdrawTx", txjson)
	} else {
		txjson, err = json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("marshal tx err. %v", err)
		}
		err = ctx.GetStub().PutState(txid, txjson)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		ctx.GetStub().SetEvent(id+"WithdrawTx", txjson)
	}
	return nil
}

// WithdrawTxUnilateral withdraw the transaction unilaterally
func (s *SmartContract) WithdrawTxUnilateral(ctx contractapi.TransactionContextInterface, txid string) error {
	txjson, err := ctx.GetStub().GetState(txid)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if txjson == nil {
		return fmt.Errorf("the transaction %s does not exist", txid)
	}
	var tx Transaction
	err = json.Unmarshal(txjson, &tx)
	if err != nil {
		return fmt.Errorf("unmarshal tx err. %v", err)
	}
	if tx.Finished {
		return fmt.Errorf("the transaction is finished")
	}
	accountJSONs, err := ctx.GetStub().GetState(tx.Seller)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSONs == nil {
		return fmt.Errorf("the account %s does not exist", tx.Seller)
	}
	accountJSONb, err := ctx.GetStub().GetState(tx.Buyer)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if accountJSONb == nil {
		return fmt.Errorf("the account %s does not exist", tx.Buyer)
	}
	tx.Finished = true
	// give the money back to the buyer
	var accountb Account
	err = json.Unmarshal(accountJSONb, &accountb)
	if err != nil {
		return fmt.Errorf("unmarshal account err. %v", err)
	}
	accountb.Amount += tx.Money
	tx.Money = 0
	//return the stake of both seller and buyer
	stakeJSONs, err := ctx.GetStub().GetState(tx.Seller + "-stake")
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	stakeJSONb, err := ctx.GetStub().GetState(tx.Buyer + "-stake")
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	var stakes Stake
	err = json.Unmarshal(stakeJSONs, &stakes)
	if err != nil {
		return fmt.Errorf("unmarshal stake err. %v", err)
	}
	var stakeb Stake
	err = json.Unmarshal(stakeJSONb, &stakeb)
	if err != nil {
		return fmt.Errorf("unmarshal stake err. %v", err)
	}
	var accounts Account
	err = json.Unmarshal(accountJSONs, &accounts)
	if err != nil {
		return fmt.Errorf("unmarshal account err. %v", err)
	}
	stakes.Returned = true
	stakeb.Returned = true
	accounts.Amount += stakes.Amount
	accounts.Mortgage -= stakes.Amount
	accountb.Amount += stakeb.Amount
	accountb.Mortgage -= stakeb.Amount
	stakeJSONs, err = json.Marshal(stakes)
	if err != nil {
		return fmt.Errorf("marshal stake err. %v", err)
	}
	stakeJSONb, err = json.Marshal(stakeb)
	if err != nil {
		return fmt.Errorf("marshal stake err. %v", err)
	}
	err = ctx.GetStub().PutState(tx.Seller+"-stake", stakeJSONs)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	err = ctx.GetStub().PutState(tx.Buyer+"-stake", stakeJSONb)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	txjson, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx err. %v", err)
	}
	err = ctx.GetStub().PutState(txid, txjson)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	accountJSONs, err = json.Marshal(accounts)
	if err != nil {
		return fmt.Errorf("marshal account err. %v", err)
	}
	accountJSONb, err = json.Marshal(accountb)
	if err != nil {
		return fmt.Errorf("marshal account err. %v", err)
	}
	err = ctx.GetStub().PutState(tx.Buyer, accountJSONb)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	err = ctx.GetStub().PutState(tx.Seller, accountJSONs)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}
	ctx.GetStub().SetEvent("WithdrawTxUnilateral", txjson)
	return nil
}

func (s *SmartContract) DeleteAllAssets(ctx contractapi.TransactionContextInterface) error {
	// Get all assets from the ledger
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return fmt.Errorf("failed to get all assets: %v", err)
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return fmt.Errorf("failed to iterate over assets: %v", err)
		}

		// Delete each asset
		err = ctx.GetStub().DelState(queryResponse.Key)
		if err != nil {
			return fmt.Errorf("failed to delete asset %s: %v", queryResponse.Key, err)
		}
	}

	return nil
}

// CreateSupervision issues a new supervision to the world state with given details.
func (s *SmartContract) CreateSupervision(ctx contractapi.TransactionContextInterface, txid string, key string) error {
	supervisiontx := SupervisionTx{
		SID:  txid + "-supervision",
		TXID: txid,
		Key:  key,
	}
	supervisionJSON, err := json.Marshal(supervisiontx)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(txid+"-supervision", supervisionJSON)
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	ctx.GetStub().SetEvent("CreateSupervision", supervisionJSON)
	return nil
}

// ReadSupervision returns the supervision key stored in the world state with given id.
func (s *SmartContract) ReadSupervision(ctx contractapi.TransactionContextInterface, sid string) (string, error) {
	supervisionJSON, err := ctx.GetStub().GetState(sid)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %v", err)
	}
	if supervisionJSON == nil {
		return "", fmt.Errorf("the supervision %s does not exist", sid)
	}

	var supervisiontx SupervisionTx
	err = json.Unmarshal(supervisionJSON, &supervisiontx)
	if err != nil {
		return "", err
	}

	return supervisiontx.Key, nil
}
