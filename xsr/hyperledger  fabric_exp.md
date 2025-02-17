# 解决wsl2连外网问题

```
cat /etc/resolv.conf
```

查看ip 172.19.80.1

然后

```
export http_proxy="http://172.19.80.1:10809"
export https_proxy="http://172.19.80.1:10809"
```



# Bring up the test network



You can run the ERC-20 token transfer scenario using the Fabric test network. Open a command terminal and navigate to the test network directory in your local clone of the `fabric-samples`. We will operate from the `test-network` directory for the remainder of the tutorial.

```
cd fabric-samples/test-network
```



Run the following command to start the test network:

```
./network.sh down
./network.sh up createChannel -c mychannel -ca
```



The test network is deployed with two peer organizations. The `createChannel` flag deploys the network with a single channel named `mychannel` with Org1 and Org2 as channel members. The -ca flag is used to deploy the network using certificate authorities. This allows you to use each organization's CA to register and enroll new users for this tutorial.



## Deploy the smart contract to the channel



You can use the test network script to deploy the 'xsr' contract to the channel that was just created. Deploy the smart contract to `mychannel` using the following command:

**For a Go Contract:**

```
./network.sh deployCC -ccn xsr -ccp ../xsr/chaincode-go/ -ccl go
```

 The above commands deploys the chaincode with short name `xsr`. The smart contract will use the default endorsement policy of majority of channel members. Since the channel has two members, this implies that we'll need to get peer endorsements from 2 out of the 2 channel members. 



Your Go chaincode depends on Go packages (like the chaincode shim) that are not part of the standard library. The source to these packages must be included in your chaincode package when it is installed to a peer. If you have structured your chaincode as a module, the easiest way to do this is to “vendor” the dependencies with `go mod vendor` before packaging your chaincode. 

