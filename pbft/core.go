package pbft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"math/big"
	"sync"
)

// fault tolerance level

type PBFT struct {
	peers      []*Peer
	cInstances map[string][]*ConsensusInstance // map client and its consensus instance
	cSeqNum    map[string]int                  // map client and its sequence number
	cPrimary   map[string]int                  // map client to a fixed primary; may change with view change

	f int
	n int

	PublicKeyByte []byte
	privateKey    *ecdsa.PrivateKey
	serverID      int
}

type Peer struct {
	ClientStream  Consensus_CStreamClient
	PublicKeyByte []byte
}

func NewPBFT(serverID int, faultTolerance int) *PBFT {

	pbft := &PBFT{
		peers:      []*Peer{},
		cInstances: make(map[string][]*ConsensusInstance),
		cSeqNum:    make(map[string]int),
		cPrimary:   make(map[string]int),
		serverID:   serverID,
		f:          faultTolerance,
		n:          3*faultTolerance + 1,
	}

	var err error
	pbft.privateKey, err = crypto.GenerateKey()
	pbft.PublicKeyByte = crypto.FromECDSAPub(&pbft.privateKey.PublicKey)

	if err != nil {
		log.Fatalf("Fail to generate private key")
	}

	return pbft
}

func (pbft *PBFT) PrimaryOfClient(clientPublicKeyByte []byte) int {
	address := publicKeyByteToAddress(clientPublicKeyByte)

	log.Print(address)
	var addressInt big.Int
	// [:2] is to remove "0X"
	_, ok := addressInt.SetString(address[2:], 16)
	if !ok {
		log.Fatalf("Fail to convert address to big int")
	}

	primary, ok := pbft.cPrimary[address]
	if !ok {
		// set default primary
		var remainder big.Int
		addressInt.DivMod(&addressInt, big.NewInt(int64(len(pbft.peers))), &remainder)
		pbft.cPrimary[address] = int(remainder.Int64())
		return pbft.cPrimary[address]
	} else {
		return primary
	}
}

func (pbft *PBFT) AddInstance(insID *InstanceID, instance *ConsensusInstance) {
	address := publicKeyByteToAddress(insID.ClientPublicKeyByte)

	seqNum := insID.SequenceNum
	// initialize map if not done before
	if pbft.cInstances[address] == nil {
		pbft.cInstances[address] = make([]*ConsensusInstance, 0)
	}

	// if instance not created before
	if len(pbft.cInstances[address]) <= seqNum {
		pbft.cInstances[address] = append(pbft.cInstances[address], instance)
	} else {
		pbft.cInstances[address][seqNum] = instance
	}
}

func (pbft *PBFT) ConnectPeers(peerAddrs []string) {
	pbft.peers = make([]*Peer, len(peerAddrs))
	var wg sync.WaitGroup
	for i, addr := range peerAddrs {
		index := i
		peerAddr := addr
		wg.Add(1)
		// exchange public key with the peer
		// use go routine so that no need to wait for a response
		go func() {
			defer wg.Done()
			conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				log.Fatalf("did not connect: %v", err)
			}
			client := NewConsensusClient(conn)

			peerPkResp, err := client.GetPublicKey(context.Background(), &PkRequest{})
			if err != nil {
				log.Fatalf("Fail to receive peer's public key")
			}

			// Contact the server and print out its response.
			stream, err := client.CStream(context.Background())
			if err != nil {
				log.Fatalf("open steam error %v", err)
			}

			pbft.peers[index] = &Peer{
				ClientStream:  stream,
				PublicKeyByte: peerPkResp.Payload,
			}
		}()
	}
	wg.Wait()
}

func publicKeyByteToAddress(pk []byte) string {
	var buf []byte
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pk[1:]) // remove EC prefix 04
	buf = hash.Sum(nil)
	publicAddress := hexutil.Encode(buf[12:])
	return publicAddress
}

func (pbft *PBFT) Instance(insID *InstanceID) (*ConsensusInstance, bool) {

	address := publicKeyByteToAddress(insID.ClientPublicKeyByte)

	if instances, ok := pbft.cInstances[address]; ok {
		if len(instances) <= insID.SequenceNum {
			return nil, false
		} else {
			return instances[insID.SequenceNum], true
		}
	}

	return nil, false
}

func verifySignature(publicKeyByte []byte, data []byte, signature []byte) bool {
	hash := crypto.Keccak256Hash(data)
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		log.Printf(err.Error())
		return false
	}
	if !bytes.Equal(publicKeyByte, sigPublicKey) {
		return false
	}
	return true
}

func (pbft *PBFT) signDataByte(dataByte []byte) []byte {
	hash := crypto.Keccak256Hash(dataByte)
	signature, err := crypto.Sign(hash.Bytes(), pbft.privateKey)
	if err != nil {
		log.Fatal(err)
	}
	return signature
}

func (pbft *PBFT) verifyClientMsg(clientMsg *ClientMsg) bool {
	// the signature should be correct
	if !verifySignature(clientMsg.InsID.ClientPublicKeyByte, clientMsg.Payload, clientMsg.Signature) {
		log.Printf("Incorrect client signature")
		return false
	}

	// the instance with seq - 1 should be finished
	if clientMsg.InsID.SequenceNum > 0 {
		previousInsID := &InstanceID{
			ClientPublicKeyByte: clientMsg.InsID.ClientPublicKeyByte,
			SequenceNum:         clientMsg.InsID.SequenceNum - 1,
		}

		previousCInstance, ok := pbft.Instance(previousInsID)
		if !ok || !previousCInstance.Committed {
			log.Printf("Instance %d should be committed", clientMsg.InsID.SequenceNum-1)
			return false
		}
	}

	// there cannot be ongoing instance with seq (TODO here not consider view change)
	if cInstance, ok := pbft.Instance(clientMsg.InsID); ok {
		log.Printf("There should be ongoing instance %d", cInstance.InsID.SequenceNum)
	}

	return true
}

// by the primary
func (pbft *PBFT) BroadcastPreprepare(clientMsg *ClientMsg) {
	log.Printf("Send a preprepare")

	if !pbft.verifyClientMsg(clientMsg) {
		return
	}

	preprepareMsg := &PreprerareMsg{
		InsID:     clientMsg.InsID,
		PrimaryID: pbft.serverID,
		ViewNum:   0, // TODO
		Timestamp: 1, // TODO
		Msg:       clientMsg,
	}

	payload, err := json.Marshal(preprepareMsg)
	if err != nil {
		log.Fatalf("cannot parse payload")
	}

	request := &CRequest{
		MsgType: CMsgType_PREPREPARE,
		Payload: payload,
	}

	// Broadcast preprepare
	pbft.Broadcast(request)
}

// by backups
func (pbft *PBFT) ReceivePreprepare(request *CRequest) {

	//log.Printf("Preprepare response")
	var preprepareMsg PreprerareMsg
	err := json.Unmarshal(request.Payload, &preprepareMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}

	// verify preprepareMsg

	// so far only verify client message
	clientMsg := preprepareMsg.Msg
	if !pbft.verifyClientMsg(clientMsg) {
		log.Printf("Incorrect client signature")
		return
	}

	// from the right primary
	primary := pbft.PrimaryOfClient(clientMsg.InsID.ClientPublicKeyByte)
	if primary != preprepareMsg.PrimaryID {
		log.Printf("From incorrect primary")
		return
	}

	// add a new instance
	pbft.AddInstance(
		preprepareMsg.InsID,
		NewConsensusInstance(preprepareMsg.InsID, preprepareMsg.Msg.MessageType, preprepareMsg.Msg.Payload))

	prepareRequest := &PrepareMsg{
		InsID:    preprepareMsg.InsID,
		ServerID: pbft.serverID,
		ViewNum:  preprepareMsg.ViewNum,
	}

	payload, err := json.Marshal(prepareRequest)
	if err != nil {
		log.Fatalf("cannot marshal request")
	}

	signature := pbft.signDataByte(payload)

	nextReq := &CRequest{
		MsgType:   CMsgType_PREPARE,
		Payload:   payload,
		Signature: signature,
	}

	pbft.Broadcast(nextReq)
}

func (pbft *PBFT) ReceivePrepare(request *CRequest) {
	//log.Printf("Preprepare response")
	var prepareMsg PrepareMsg
	err := json.Unmarshal(request.Payload, &prepareMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}

	// verify prepare message
	// check the signature
	fromServer := prepareMsg.ServerID
	fromServerPublicKeyByte := pbft.peers[fromServer].PublicKeyByte
	if !verifySignature(fromServerPublicKeyByte, request.Payload, request.Signature) {
		log.Printf("Incorrect prepare signature")
	}

	cInstance, ok := pbft.Instance(prepareMsg.InsID)
	if !ok {
		log.Printf("should receive preprepare first before accepting a prepare")
		return
	}

	cInstance.Lock()
	defer cInstance.Unlock()
	cInstance.AddPrepareMsg(&prepareMsg)

	// after collecting enough prepares
	if len(cInstance.Prepares) == 2*pbft.f+1 {
		log.Printf("Request prepared")
		cInstance.Prepared = true
		commitMsg := &CommitMsg{
			InsID:    prepareMsg.InsID,
			ServerID: pbft.serverID,
			ViewNum:  prepareMsg.ViewNum,
		}

		payload, err := json.Marshal(commitMsg)
		if err != nil {
			log.Fatalf("cannot marshal request")
		}

		signature := pbft.signDataByte(payload)

		nextRequest := &CRequest{
			MsgType:   CMsgType_COMMIT,
			Payload:   payload,
			Signature: signature,
		}

		pbft.Broadcast(nextRequest)
	}
}

func (pbft *PBFT) ReceiveCommit(request *CRequest) {
	//log.Printf("Preprepare response")
	var commitMsg CommitMsg
	err := json.Unmarshal(request.Payload, &commitMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}

	// verify prepare message
	// check the signature
	fromServer := commitMsg.ServerID
	fromServerPublicKeyByte := pbft.peers[fromServer].PublicKeyByte

	if !verifySignature(fromServerPublicKeyByte, request.Payload, request.Signature) {
		log.Printf("Incorrect commit signature")
	}

	cInstance, ok := pbft.Instance(commitMsg.InsID)
	if !ok {
		log.Printf("should receive preprepare first before accepting a prepare")
		return
	}

	cInstance.Lock()
	defer cInstance.Unlock()
	cInstance.AddCommitMsg(&commitMsg)

	// after collecting enough prepares
	if len(cInstance.Commits) == 2*pbft.f+1 {
		log.Printf("Request committed")
		cInstance.Prepared = true
		cInstance.Committed = true
		address := publicKeyByteToAddress(cInstance.InsID.ClientPublicKeyByte)
		pbft.cSeqNum[address] += 1
		// TODO execute operation

		// response to the client
	}
}

func (pbft *PBFT) Broadcast(request *CRequest) {

	for _, peer := range pbft.peers {
		err := peer.ClientStream.Send(request)
		if err != nil {
			log.Fatalf("fail to send preprepare msg %v", err)
		}
	}
}

// Backup event loop is to react on request
func (pbft *PBFT) EventLoop(stream Consensus_CStreamServer, request *CRequest) {
	switch request.MsgType {
	case CMsgType_PREPREPARE:
		// on receive preprepare, broadcast prepare
		pbft.ReceivePreprepare(request)
	case CMsgType_PREPARE:
		// on receiving enough prepare, broadcast commit
		pbft.ReceivePrepare(request)
	case CMsgType_COMMIT:
		// on receive enough commit, execute operation
		pbft.ReceiveCommit(request)
	}
}
