package pbft

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"sync"
)

type InstanceID struct {
	ClientPublicKeyByte []byte
	SequenceNum         int
}

type ConsensusInstance struct {
	InsID *InstanceID
	//MsgType int    // belongs to PAYMENT/OFF2ON/ON2OFF
	//Payload []byte // store the exact message
	//Primary int    //

	//Quorums   []Consensus_CStreamClient
	//Preprepares []*PreprepareResponse
	PreprerareMsg      *PreprerareMsg
	PrepareMsg         *PrepareMsg
	CommitMsg          *CommitMsg
	AggregatedPrepares *AggregatedPrepareMsg // store prepare response from backups
	AggregatedCommits  *AggregatedCommitMsg  // store commit response from backups
	Prepared           bool                  // True given 2f+1 prepare message
	Committed          bool                  // True given 2f+1 commit messages
	mu                 *sync.Mutex           // prevent concurrent access to the above five objects
}

func NewConsensusInstance(preprepareMsg *PreprerareMsg) *ConsensusInstance {
	// set up prepare message according to preprepareMsg
	clientMsgByte, err := json.Marshal(preprepareMsg.Msg)
	if err != nil {
		panic(err)
	}
	clientMsgDigest := crypto.Keccak256Hash(clientMsgByte).Bytes()
	prepareMsg := &PrepareMsg{
		InsID:     preprepareMsg.InsID,
		ViewNum:   preprepareMsg.ViewNum,
		Timestamp: preprepareMsg.ViewNum,
		MsgDigest: clientMsgDigest,
	}

	commitMsg := &CommitMsg{
		InsID:     preprepareMsg.InsID,
		ViewNum:   preprepareMsg.ViewNum,
		Timestamp: preprepareMsg.ViewNum,
		MsgDigest: clientMsgDigest,
	}

	return &ConsensusInstance{
		InsID:         preprepareMsg.InsID,
		PreprerareMsg: preprepareMsg,
		PrepareMsg:    prepareMsg,
		CommitMsg:     commitMsg,
		//MsgType: msgType,
		//Payload: payload,
		//
		//Primary: primary,
		//Preprepares: []*PreprepareResponse{},
		AggregatedPrepares: &AggregatedPrepareMsg{
			PrepareMsgs: []*PrepareMsg{},
			Signatures:  []*Signature{},
		},
		AggregatedCommits: &AggregatedCommitMsg{
			CommitMsgs: []*CommitMsg{},
			Signatures: []*Signature{},
		},
		Prepared:  false,
		Committed: false,

		mu: &sync.Mutex{},
	}
}

func (c *ConsensusInstance) Lock() {
	c.mu.Lock()
}

func (c *ConsensusInstance) Unlock() {
	c.mu.Unlock()
}

//func (c *ConsensusInstance) AddPreprepare(response *PreprepareResponse) {
//	c.Preprepares = append(c.Preprepares, response)
//}

//func (c *ConsensusInstance) AddPrepareMsg(prepareMsg *PrepareMsg) {
//	c.Prepares = append(c.Prepares, prepareMsg)
//}
//
//func (c *ConsensusInstance) AddCommitMsg(request *CommitMsg) {
//	c.Commits = append(c.Commits, request)
//}
