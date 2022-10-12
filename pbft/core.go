package pbft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/orcaman/concurrent-map/v2"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

var commitedCount atomic.Int32
var commitCount atomic.Int32 // just a single commit message
var preparedCount atomic.Int32
var prepareCount atomic.Int32 // just a single prepare message
var preprepareCount atomic.Int32
var Start time.Time
var PRINT_INTERVAL int32 = 200

// fault tolerance level

type PBFT struct {
	peers      []*Peer
	cInstances cmap.ConcurrentMap[[]*ConsensusInstance] // map client and its consensus instance
	cSeqNum    cmap.ConcurrentMap[int]                  // map client and its sequence number

	f int
	n int

	PublicKeyByte []byte
	privateKey    *ecdsa.PrivateKey
	serverID      int32
}

type Peer struct {
	ClientStream  Consensus_PBFTMessagingClient
	PublicKeyByte []byte
	mu            sync.Mutex
}

func (p *Peer) SendRequest(request *PbftRequest) {
	// prevent concurrent access to stream.Send
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ClientStream == nil {
		log.Fatalf("Unexpected error")
	}
	err := p.ClientStream.Send(request)
	if err != nil {
		log.Fatalf("fail to send preprepare msg %v", err)
	}
}

func NewPBFT(serverID int32, faultTolerance int) *PBFT {

	pbft := &PBFT{
		peers:      []*Peer{},
		cInstances: cmap.New[[]*ConsensusInstance](),
		cSeqNum:    cmap.New[int](),
		//cPrimary:   make(map[string]int),
		serverID: serverID,
		f:        faultTolerance,
		n:        3*faultTolerance + 1,
	}

	var err error
	pbft.privateKey, err = crypto.GenerateKey()
	pbft.PublicKeyByte = crypto.FromECDSAPub(&pbft.privateKey.PublicKey)

	if err != nil {
		log.Fatalf("Fail to generate private key")
	}

	return pbft
}

//func (pbft *PBFT) PrimaryOfClient(clientPublicKeyByte []byte) int {
//	address := publicKeyByteToAddress(clientPublicKeyByte)
//
//	//log.Print(address)
//	var addressInt big.Int
//	// [:2] is to remove "0X"
//	_, ok := addressInt.SetString(address[2:], 16)
//	if !ok {
//		log.Fatalf("Fail to convert address to big int")
//	}
//
//	primary, ok := pbft.cPrimary[address]
//	if !ok {
//		// set default primary
//		var remainder big.Int
//		addressInt.DivMod(&addressInt, big.NewInt(int64(len(pbft.peers))), &remainder)
//		pbft.cPrimary[address] = int(remainder.Int64())
//		return pbft.cPrimary[address]
//	} else {
//		return primary
//	}
//}

func (pbft *PBFT) AddInstance(insID *InstanceID, instance *ConsensusInstance) {
	address := publicKeyByteToAddress(insID.ClientPublicKeyByte)

	seqNum := insID.SequenceNum
	// initialize map if not done before
	//if pbft.cInstances.Count(address) == 0 {
	//	pbft.cInstances.Get()
	//	pbft.cInstances[address] = make([]*ConsensusInstance, 0)
	//}

	pbft.cInstances.SetIfAbsent(address, make([]*ConsensusInstance, 0))

	// if instance not created before
	cInstances, _ := pbft.cInstances.Get(address)
	if len(cInstances) <= seqNum {
		pbft.cInstances.Set(address, append(cInstances, instance))
	} else {
		// update the old
		cInstances[seqNum] = instance
	}
}

func (pbft *PBFT) GetInstance(insID *InstanceID) (*ConsensusInstance, bool) {
	address := publicKeyByteToAddress(insID.ClientPublicKeyByte)
	if cInstances, ok := pbft.cInstances.Get(address); ok {
		if len(cInstances) > insID.SequenceNum {
			return cInstances[insID.SequenceNum], true
		} else {
			return nil, false
		}
	} else {
		return nil, false
	}
}

func (pbft *PBFT) ConnectPeers(serverAddrs []string) {
	pbft.peers = make([]*Peer, len(serverAddrs))
	var wg sync.WaitGroup
	for i, addr := range serverAddrs {
		if int32(i) == pbft.serverID {
			pbft.peers[i] = &Peer{
				ClientStream:  nil,
				PublicKeyByte: pbft.PublicKeyByte,
			}
		}
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
				log.Fatalf("Fail to receive peer's public key: %v", err)
			}

			// Contact the server and print out its response.
			stream, err := client.PBFTMessaging(context.Background())
			if err != nil {
				log.Fatalf("open steam error %v", err)
			}

			pbft.peers[index] = &Peer{
				ClientStream:  stream,
				PublicKeyByte: peerPkResp.Payload,
			}
			log.Printf("add peer %d", index)
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

	if cInstances, ok := pbft.cInstances.Get(address); ok {
		if len(cInstances) <= insID.SequenceNum {
			return nil, false
		} else {
			return cInstances[insID.SequenceNum], true
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
	//log.Printf("Send a preprepare")

	if !pbft.verifyClientMsg(clientMsg) {
		//return nil
		panic("fail to verify client message")
	}

	preprepareMsg := &PreprerareMsg{
		InsID:     clientMsg.InsID,
		ViewNum:   0, // TODO
		Timestamp: 1, // TODO
		Msg:       clientMsg,
	}

	// prepare
	pbft.prepare(preprepareMsg)
	// add to aggregated signature

	payload, err := json.Marshal(preprepareMsg)
	if err != nil {
		log.Fatalf("cannot parse payload")
	}

	request := &PbftRequest{
		MsgType:  CMsgType_PREPREPARE,
		Payload:  payload,
		ServerID: int32(pbft.serverID),
	}

	// Broadcast preprepare
	pbft.Broadcast(request)

	value := preprepareCount.Add(1)
	if value%PRINT_INTERVAL == 0 {
		log.Printf("preprepare sent %d", value)
	}

	//return make(chan int)
}

// update local state
func (pbft *PBFT) prepare(preprepareMsg *PreprerareMsg) *PbftRequest {
	// add a new instance
	cInstance := NewConsensusInstance(preprepareMsg)
	pbft.AddInstance(
		preprepareMsg.InsID, cInstance)

	prepareMsg := cInstance.PrepareMsg

	prepareMsgByte, err := json.Marshal(prepareMsg)
	if err != nil {
		panic(err)
	}
	signatureByte := pbft.signDataByte(prepareMsgByte)
	signature := &Signature{
		Payload:  signatureByte,
		ServerID: pbft.serverID,
	}

	if preprepareMsg.Msg.Primary == pbft.serverID {
		cInstance.AggregatedPrepares.appendPrepareMsg(prepareMsg, signature)
		cInstance.AggregatedPrepares.InsID = prepareMsg.InsID
		return nil
	} else {
		nextReq := &PbftRequest{
			ServerID:      int32(pbft.serverID),
			MsgType:       CMsgType_PREPARE,
			Payload:       prepareMsgByte,
			SignatureByte: pbft.signDataByte(prepareMsgByte),
		}
		return nextReq
	}
}

// used by backups
func (pbft *PBFT) ReceivePreprepare(request *PbftRequest) {
	//time.Sleep(1 * time.Second)
	//log.Printf("Preprepare response")
	var preprepareMsg PreprerareMsg
	err := json.Unmarshal(request.Payload, &preprepareMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
		return
	}

	// verify preprepareMsg

	// so far only verify client message
	clientMsg := preprepareMsg.Msg
	if !pbft.verifyClientMsg(clientMsg) {
		log.Fatalf("Incorrect client signature")
	}

	// from the right primary
	//primary := pbft.PrimaryOfClient(clientMsg.InsID.ClientPublicKeyByte)
	//if primary != preprepareMsg.PrimaryID {
	//	log.Printf("From incorrect primary")
	//	return
	//}
	primary := clientMsg.Primary
	if primary != request.ServerID {
		log.Fatalf("From incorrect primary")
	}

	nextReq := pbft.prepare(&preprepareMsg)
	//pbft.Broadcast(nextReq)
	pbft.SendToPrimary(primary, nextReq)

	value := prepareCount.Add(1)
	if value%PRINT_INTERVAL == 0 {
		log.Printf("prepare sent %d", value)
	}
}

func (pbft *PBFT) prepared(msg *AggregatedPrepareMsg) *PbftRequest {
	cInstance, ok := pbft.GetInstance(msg.InsID)
	if !ok {
		panic(errors.New("instance not exist"))
	}
	cInstance.Prepared = true

	value := preparedCount.Add(1)

	if value%PRINT_INTERVAL == 0 {
		log.Printf("prepared count %d, time %s", value, time.Since(Start))
	}

	commitMsg := cInstance.CommitMsg

	commitMsgByte, err := json.Marshal(commitMsg)
	if err != nil {
		panic(err)
	}
	signatureByte := pbft.signDataByte(commitMsgByte)
	signature := &Signature{
		Payload:  signatureByte,
		ServerID: pbft.serverID,
	}

	if cInstance.PreprerareMsg.Msg.Primary == pbft.serverID {
		cInstance.AggregatedCommits.AppendCommitMsg(commitMsg, signature)
		cInstance.AggregatedCommits.InsID = commitMsg.InsID
		return nil
	} else {
		nextReq := &PbftRequest{
			ServerID:      int32(pbft.serverID),
			MsgType:       CMsgType_COMMIT,
			Payload:       commitMsgByte,
			SignatureByte: pbft.signDataByte(commitMsgByte),
		}
		return nextReq
	}
}

func (pbft *PBFT) sendAggregatePreparesToPeers(aggregatedPrepares *AggregatedPrepareMsg, peerIDs []int32) {
	payload, err := json.Marshal(aggregatedPrepares)
	if err != nil {
		log.Fatalf("cannot marshal request")
	}

	//log.Printf("aggregated prepare length %d", cInstance.AggregatedPrepares.Length)
	nextRequest := &PbftRequest{
		MsgType:  CMsgType_AGGREGATED_PREPARE,
		Payload:  payload,
		ServerID: pbft.serverID,
	}

	for _, peerID := range peerIDs {
		peer := pbft.peers[peerID]
		peer.SendRequest(nextRequest)
	}
}

// used by the primary to aggregate prepare message
func (pbft *PBFT) ReceivePrepare(request *PbftRequest) {
	//log.Printf("Preprepare response")
	var prepareMsg PrepareMsg
	err := json.Unmarshal(request.Payload, &prepareMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}

	// discard unmatched prepare
	var baselinePrepareMsg *PrepareMsg
	cInstance, ok := pbft.GetInstance(prepareMsg.InsID)
	if !ok {
		log.Fatalf("preprepare should exist before receiving a prepare")
	} else {
		baselinePrepareMsg = cInstance.PrepareMsg
	}

	// verify prepare message
	// should be equal to the basic line
	if !reflect.DeepEqual(baselinePrepareMsg, &prepareMsg) {
		log.Fatalf("Prepare message from backup should match that of the primary")
	}

	cInstance.Lock()
	defer cInstance.Unlock()
	// respond with aggregated signature
	if cInstance.Prepared {
		pbft.sendAggregatePreparesToPeers(cInstance.AggregatedPrepares, []int32{request.ServerID})
		return
	}

	// check the signature
	fromServer := request.ServerID
	fromServerPublicKeyByte := pbft.peers[fromServer].PublicKeyByte
	if !verifySignature(fromServerPublicKeyByte, request.Payload, request.SignatureByte) {
		log.Fatalf("Incorrect prepare signature")
	}

	signature := &Signature{
		Payload:  request.SignatureByte,
		ServerID: fromServer,
	}
	cInstance.AggregatedPrepares.appendPrepareMsg(&prepareMsg, signature)
	//cInstance.AddPrepareMsg(&prepareMsg)

	// after collecting enough prepares
	if cInstance.AggregatedPrepares.Length == 2*pbft.f+1 {
		//log.Printf("Request prepared")

		pbft.prepared(cInstance.AggregatedPrepares)

		//Only respond to those who has sent prepare
		// This makes sure that those peers have received the client msg in preprepare
		peerIDs := []int32{}
		for _, sig := range (cInstance.AggregatedPrepares).Signatures {
			serverID := sig.ServerID
			// skip if send to itself
			if serverID == pbft.serverID {
				continue
			}
			peerIDs = append(peerIDs, serverID)
		}
		pbft.sendAggregatePreparesToPeers(cInstance.AggregatedPrepares, peerIDs)
		//log.Printf("broadcast aggreagated prepares")
		//pbft.SendToPrimary()
	}
}

func (pbft *PBFT) ReceiveAggregatedPrepare(request *PbftRequest) {
	var aggregatedPrepareMsg AggregatedPrepareMsg
	err := json.Unmarshal(request.Payload, &aggregatedPrepareMsg)
	if err != nil {
		panic(err)
	}
	// should have 2f+1
	if aggregatedPrepareMsg.Length != 2*pbft.f+1 {
		panic(errors.New("should have 2f+1 prepares"))
	}

	// must receive preprepare before
	cInstance, ok := pbft.GetInstance(aggregatedPrepareMsg.InsID)
	if !ok {
		log.Printf("Must receive preprepare before")
		return
	}

	baselinePrepareMsg := cInstance.PrepareMsg

	for i := 0; i < 2*pbft.f+1; i++ {
		prepareMsg := aggregatedPrepareMsg.PrepareMsgs[i]
		signature := aggregatedPrepareMsg.Signatures[i]
		serverPKByte := pbft.peers[signature.ServerID].PublicKeyByte

		msgByte, err := json.Marshal(prepareMsg)
		if err != nil {
			panic(err)
		}

		// verify signature
		if !verifySignature(serverPKByte, msgByte, signature.Payload) {
			panic(errors.New("Fail to verify signature"))
		}

		// 2f+1 should match
		if !reflect.DeepEqual(baselinePrepareMsg, prepareMsg) {
			log.Fatalf("2f+1 prepare messages should match")
		}
	}

	nextReq := pbft.prepared(&aggregatedPrepareMsg)
	pbft.SendToPrimary(request.ServerID, nextReq)

	//value := commitCount.Add(1)
	//
	//if value%PRINT_INTERVAL == 0 {
	//	log.Printf("commit sent %d", value)
	//}
}

func (pbft *PBFT) commit(msg *AggregatedCommitMsg) {
	cInstance, ok := pbft.GetInstance(msg.InsID)
	if !ok {
		panic(errors.New("instance not exist"))
	}
	cInstance.Committed = true

	value := commitedCount.Add(1)

	if value%PRINT_INTERVAL == 0 {
		log.Printf("commit count %d, time %s", value, time.Since(Start))
	}
	// execute opeartion
}

func (pbft *PBFT) sendAggregateCommitsToPeers(aggregatedCommits *AggregatedCommitMsg, peerIDs []int32) {
	payload, err := json.Marshal(aggregatedCommits)
	if err != nil {
		log.Fatalf("cannot marshal request")
	}

	//log.Printf("aggregated prepare length %d", cInstance.AggregatedPrepares.Length)
	nextRequest := &PbftRequest{
		MsgType:  CMsgType_AGGREGATED_COMMIT,
		Payload:  payload,
		ServerID: pbft.serverID,
	}

	for _, peerID := range peerIDs {
		peer := pbft.peers[peerID]
		peer.SendRequest(nextRequest)
	}
}

// used by the primary to aggregate commit
func (pbft *PBFT) ReceiveCommit(request *PbftRequest) {
	//log.Printf("Preprepare response")
	var commitMsg CommitMsg
	err := json.Unmarshal(request.Payload, &commitMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}

	// discard unmatched prepare
	var baselineCommitMsg *CommitMsg
	cInstance, ok := pbft.GetInstance(commitMsg.InsID)
	if !ok {
		log.Fatalf("preprepare should exist before receiving a commit")
	} else {
		baselineCommitMsg = cInstance.CommitMsg
	}

	cInstance.Lock()
	defer cInstance.Unlock()
	// skip if already committed
	if cInstance.Committed {
		pbft.sendAggregateCommitsToPeers(cInstance.AggregatedCommits, []int32{request.ServerID})
		return
	}

	// verify prepare message
	// should be equal to the basic line
	if !reflect.DeepEqual(baselineCommitMsg, &commitMsg) {
		log.Fatalf("commit message from backup should match that of the primary")
	}

	// check the signature
	fromServer := request.ServerID
	fromServerPublicKeyByte := pbft.peers[fromServer].PublicKeyByte
	if !verifySignature(fromServerPublicKeyByte, request.Payload, request.SignatureByte) {
		log.Fatalf("Incorrect commit signature")
	}

	signature := &Signature{
		Payload:  request.SignatureByte,
		ServerID: fromServer,
	}
	cInstance.AggregatedCommits.AppendCommitMsg(&commitMsg, signature)
	//cInstance.AddPrepareMsg(&prepareMsg)

	// after collecting enough prepares
	if cInstance.AggregatedCommits.Length == 2*pbft.f+1 {
		//log.Printf("Request prepared")

		pbft.commit(cInstance.AggregatedCommits)

		//Only respond to those who has sent commit
		peerIDs := []int32{}
		for _, sig := range (cInstance.AggregatedCommits).Signatures {
			serverID := sig.ServerID
			// skip if send to itself
			if serverID == pbft.serverID {
				continue
			}
			peerIDs = append(peerIDs, serverID)
		}

		pbft.sendAggregateCommitsToPeers(cInstance.AggregatedCommits, peerIDs)
		//pbft.SendToPrimary()
	}
}

func (pbft *PBFT) ReceiveAggregatedCommit(request *PbftRequest) {
	var aggregatedCommitMsg AggregatedCommitMsg
	err := json.Unmarshal(request.Payload, &aggregatedCommitMsg)
	if err != nil {
		panic(err)
	}
	// should have 2f+1
	if aggregatedCommitMsg.Length != 2*pbft.f+1 {
		panic(errors.New("should have 2f+1 prepares"))
	}

	// must receive preprepare before
	cInstance, ok := pbft.GetInstance(aggregatedCommitMsg.InsID)
	if !ok {
		log.Printf("Must receive preprepare before")
		return
	}

	baselineCommitMsg := cInstance.CommitMsg

	for i := 0; i < 2*pbft.f+1; i++ {
		commitMsg := aggregatedCommitMsg.CommitMsgs[i]
		signature := aggregatedCommitMsg.Signatures[i]
		serverPKByte := pbft.peers[signature.ServerID].PublicKeyByte

		msgByte, err := json.Marshal(commitMsg)
		if err != nil {
			panic(err)
		}

		// verify signature
		if !verifySignature(serverPKByte, msgByte, signature.Payload) {
			panic(errors.New("Fail to verify signature"))
		}

		// 2f+1 should match
		if !reflect.DeepEqual(baselineCommitMsg, commitMsg) {
			log.Fatalf("2f+1 prepare messages should match")
		}
	}
	pbft.commit(&aggregatedCommitMsg)
}

func (pbft *PBFT) SendToPrimary(primaryID int32, request *PbftRequest) {
	if primaryID == pbft.serverID {
		log.Fatalf("unexpected error")
	}
	primary := pbft.peers[primaryID]
	primary.SendRequest(request)
}

func (pbft *PBFT) Broadcast(request *PbftRequest) { // not include itself
	for i, peer := range pbft.peers {
		if int32(i) == pbft.serverID {
			continue
		}
		peer.SendRequest(request)
	}
}

//func (pbft *PBFT) PrimaryEventLoop(request *PbftRequest) {
//	switch request.MsgType {
//
//	}
//}

// Backup event loop is to react on request
func (pbft *PBFT) EventLoop(request *PbftRequest) {
	switch request.MsgType {
	case CMsgType_PREPREPARE:
		pbft.ReceivePreprepare(request) // send prepare to the commit
	case CMsgType_PREPARE:
		pbft.ReceivePrepare(request) // used by the primary
	case CMsgType_AGGREGATED_PREPARE:
		pbft.ReceiveAggregatedPrepare(request) // used by the backup
	case CMsgType_COMMIT:
		pbft.ReceiveCommit(request)
	case CMsgType_AGGREGATED_COMMIT:
		pbft.ReceiveAggregatedCommit(request)
	}
}
