package pbft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"sync"
)

// fault tolerance level

type PBFT struct {
	peers      []*Peer
	cInstances map[int][]*ConsensusInstance

	f int
	n int

	privateKey *ecdsa.PrivateKey
	serverID   int
}

type Peer struct {
	ClientStream Consensus_CStreamClient
	PublicKey    *ecdsa.PublicKey
}

func NewPBFT(serverID int, faultTolerance int) *PBFT {

	pbft := &PBFT{
		peers:      []*Peer{},
		cInstances: make(map[int][]*ConsensusInstance),
		serverID:   serverID,
		f:          faultTolerance,
		n:          3*faultTolerance + 1,
	}

	var err error
	pbft.privateKey, err = crypto.GenerateKey()

	if err != nil {
		log.Fatalf("Fail to generate private key")
	}

	return pbft
}

func (pbft *PBFT) PublicKey() *ecdsa.PublicKey {
	return &pbft.privateKey.PublicKey
}

func (pbft *PBFT) AddInstance(insID *InstanceID, instance *ConsensusInstance) {
	clientID := insID.ClientPublicKey
	seqNum := insID.SequenceNum
	// initialize map if not done before
	if pbft.cInstances[clientID] == nil {
		pbft.cInstances[clientID] = make([]*ConsensusInstance, 0)
	}

	// if instance not created before
	if len(pbft.cInstances[clientID]) <= seqNum {
		pbft.cInstances[clientID] = append(pbft.cInstances[clientID], instance)
	} else {
		pbft.cInstances[clientID][seqNum] = instance
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

			peerPK, err := crypto.UnmarshalPubkey(peerPkResp.Payload)
			if err != nil {
				log.Fatalf("Cannot unmarshal public key payload %v", err)
			}

			// Contact the server and print out its response.
			stream, err := client.CStream(context.Background())
			if err != nil {
				log.Fatalf("open steam error %v", err)
			}

			pbft.peers[index] = &Peer{
				ClientStream: stream,
				PublicKey:    peerPK,
			}
		}()
	}
	wg.Wait()
}

func (pbft *PBFT) Instance(insID *InstanceID) (*ConsensusInstance, bool) {
	clientID := insID.ClientID
	seqNum := insID.SequenceNum

	if instances, ok := pbft.cInstances[clientID]; ok {
		if len(instances) <= seqNum {
			return nil, false
		} else {
			return instances[seqNum], true
		}
	}
	return nil, false
}

func verifyClientMsg(clientMsg *ClientMsg) bool {
	// verify client signature
	publicKeyBytes := crypto.FromECDSAPub(clientMsg.InsID.ClientPublicKey)
	hash := crypto.Keccak256Hash(clientMsg.Payload)
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), clientMsg.Signature)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(publicKeyBytes, sigPublicKey) {
		log.Printf("Incorrect client signature")
		return false
	}
	// verify sequence number  // TODO

	// verify view number // TODO

	return true
}

func (pbft *PBFT) signPayload(payload []byte) []byte {
	hash := crypto.Keccak256Hash(payload)
	signature, err := crypto.Sign(hash.Bytes(), pbft.privateKey)
	if err != nil {
		log.Fatal(err)
	}
	return signature
}

// by the primary
func (pbft *PBFT) BroadcastPreprepare(clientMsg *ClientMsg) {
	log.Printf("Send a preprepare")

	if !verifyClientMsg(clientMsg) {
		return
	}

	// create a new instance
	instance := NewConsensusInstance(clientMsg.InsID, clientMsg.MessageType, clientMsg.Payload)
	pbft.AddInstance(clientMsg.InsID, instance)

	preprepareMsg := &PreprerareMsg{
		InsID:     clientMsg.InsID,
		PrimaryID: pbft.serverID,
		ViewNum:   0,
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

func (pbft *PBFT) verifyPreprepareMsg(preprepareMsg *PreprerareMsg) bool {

	// so far only verify client message
	if !verifyClientMsg(preprepareMsg.Msg) {
		return false
	}

	// TODO verify it is the right primary
	// TODO verify sequence number and view number
	return true
}

// by backups
func (pbft *PBFT) ReceivePreprepare(stream Consensus_CStreamServer, request *CRequest) {

	//log.Printf("Preprepare response")
	var preprepareMsg PreprerareMsg
	err := json.Unmarshal(request.Payload, &preprepareMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}

	// verify preprepareMsg

	if !pbft.verifyPreprepareMsg(&preprepareMsg) {
		return
	}

	// Create an instance for backups
	if pbft.serverID != preprepareMsg.PrimaryID {
		pbft.AddInstance(
			preprepareMsg.InsID,
			NewConsensusInstance(preprepareMsg.InsID, preprepareMsg.Msg.MessageType, preprepareMsg.Msg.Payload))
	}

	prepareRequest := &PrepareMsg{
		InsID:    preprepareMsg.InsID,
		ServerID: pbft.serverID,
		ViewNum:  preprepareMsg.ViewNum,
	}

	payload, err := json.Marshal(prepareRequest)
	if err != nil {
		log.Fatalf("cannot marshal request")
	}

	signature := pbft.signPayload(payload)

	response := &CResponse{
		MsgType:   CMsgType_PREPARE,
		Payload:   payload,
		Signature: signature,
	}

	pbft.Broadcast()
}

func (pbft *PBFT) ReceivePrepare(stream Consensus_CStreamServer, request *CRequest) {
	//log.Printf("Preprepare response")
	var aggregatedPrepareMsg AggregatedPrepareMsg
	err := json.Unmarshal(request.Payload, &aggregatedPrepareMsg)
	if err != nil {
		log.Fatalf("cannot unmarshal payload")
	}
	//log.Printf("Receive aggregated prepares from the primary")
	// process preprepare response

	//cInstance, _ := pbft.Instance(prepareResponse.InsID)

	commitMsg := &CommitMsg{
		InsID:    aggregatedPrepareMsg.InsID,
		ServerID: pbft.serverID,
		ViewNum:  aggregatedPrepareMsg.ViewNum,
		//Timestamp: preprepareResponse
		//MsgDigest: []byte("test"),
	}

	payload, err := json.Marshal(commitMsg)
	if err != nil {
		log.Fatalf("cannot marshal request")
	}

	response := &CResponse{
		MsgType: CMsgType_COMMIT,
		Payload: payload,
	}

	err = stream.Send(response)
	if err != nil {
		log.Fatalf("Fail to send commit message")
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

func (pbft *PBFT) AggregatePrepare(response *CResponse) {
	// aggregate prepares
	var prepareMsg PrepareMsg
	err := json.Unmarshal(response.Payload, &prepareMsg)
	if err != nil {
		log.Printf("Cannot unmarshal prepare request")
	}

	cInstance, ok := pbft.Instance(prepareMsg.InsID)
	if !ok {
		log.Fatalf("instance not exist")
	}
	cInstance.Lock()
	defer cInstance.Unlock()
	cInstance.AddPrepareMsg(&prepareMsg)
	if len(cInstance.Prepares) == 2*pbft.f+1 {
		log.Printf("broadcast aggregated prepares")
		//TODO
		aggregatedPrepares := &AggregatedPrepareMsg{
			InsID:    prepareMsg.InsID,
			ServerID: pbft.serverID,
			ViewNum:  prepareMsg.ViewNum,
			//Timestamp: preprepareResponse
			//MsgDigest: []byte("test"),
			Signature: []byte("signature"),
		}
		payload, err := json.Marshal(aggregatedPrepares)
		if err != nil {
			log.Fatalf("cannot marshal request")
		}
		pbft.Broadcast(&CRequest{
			MsgType: CMsgType_AGGREGATED_PREPARE,
			Payload: payload,
		})
	}
	// broadcast a prepare response after collecting prepares
}

func (pbft *PBFT) AggregateCommit(response *CResponse) {
	// aggregate commits
	var commitMsg CommitMsg
	err := json.Unmarshal(response.Payload, &commitMsg)
	if err != nil {
		log.Printf("Cannot unmarshal prepare request")
	}

	cInstance, ok := pbft.Instance(commitMsg.InsID)
	if !ok {
		log.Fatalf("instance not exist")
	}

	cInstance.Lock()
	defer cInstance.Unlock()
	cInstance.AddCommitMsg(&commitMsg)
	if len(cInstance.Commits) == 2*pbft.f+1 {
		//TODO
		log.Printf("broadcast aggregated commits")
		aggregatedCommitMsg := &AggregatedCommitMsg{
			InsID:    commitMsg.InsID,
			ServerID: pbft.serverID,
			ViewNum:  commitMsg.ViewNum,
			//Timestamp: preprepareResponse
			//MsgDigest: []byte("test"),
			Signature: []byte("signature"),
		}
		payload, err := json.Marshal(aggregatedCommitMsg)
		if err != nil {
			log.Fatalf("cannot marshal request")
		}
		pbft.Broadcast(&CRequest{
			MsgType: CMsgType_AGGREGATED_COMMIT,
			Payload: payload,
		})
	}
	// broadcast a prepare response after collecting prepares
}

func (pbft *PBFT) Commit() {
	// TODO
}

// Backup event loop is to react on request
func (pbft *PBFT) BackupEventLoop(stream Consensus_CStreamServer, request *CRequest) {
	switch request.MsgType {
	case CMsgType_PREPREPARE:
		// on receive preprepare, broadcast prepare
		pbft.ReceivePreprepare(stream, request)
	case CMsgType_PREPARE:
		// on receiving enough prepare, broadcast commit
		pbft.ReceivePrepare(stream, request)
	case CMsgType_COMMIT:
		// on receive enough commit, execute operation
		log.Printf("on receive a commit response, execute the operation")
		pbft.ReceiveCommit(stream, request)
	}
}

// Primary event loop is to react on response
func (pbft *PBFT) PrimaryEventLoop() {
	var wg sync.WaitGroup
	for i, _ := range pbft.peers {
		peer := pbft.peers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				response, err := peer.ClientStream.Recv()
				if err != nil {
					log.Fatalf("fail to receive response")
				}
				switch response.MsgType {
				case CMsgType_PREPARE:
					pbft.ReceivePrepare()
				}
			}
		}()
	}
	wg.Wait()
}

//func ConsensusInstanceID(clientID int, sequenceNum int) string {
//	return strconv.Itoa(clientID) + "#" + strconv.Itoa(sequenceNum)
//}
