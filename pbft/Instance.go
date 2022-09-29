package pbft

import (
	"crypto/ecdsa"
	"sync"
)

type InstanceID struct {
	ClientPublicKey *ecdsa.PublicKey
	SequenceNum     int
}

type ConsensusInstance struct {
	InsID   *InstanceID
	MsgType int    // belongs to PAYMENT/OFF2ON/ON2OFF
	Payload []byte // store the exact message

	//Quorums   []Consensus_CStreamClient
	//Preprepares []*PreprepareResponse
	Prepares  []*PrepareMsg // store prepare response from backups
	Commits   []*CommitMsg  // store commit response from backups
	Prepared  bool          // True given 2f+1 prepare message
	Committed bool          // True given 2f+1 commit messages
	mu        *sync.Mutex   // prevent concurrent access to the above five objects
}

func NewConsensusInstance(insID *InstanceID, msgType int, payload []byte) *ConsensusInstance {
	return &ConsensusInstance{
		InsID:   insID,
		MsgType: msgType,
		Payload: payload,
		//Preprepares: []*PreprepareResponse{},
		Prepares:  []*PrepareMsg{},
		Commits:   []*CommitMsg{},
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

func (c *ConsensusInstance) AddPrepareMsg(prepareMsg *PrepareMsg) {
	c.Prepares = append(c.Prepares, prepareMsg)
}

func (c *ConsensusInstance) AddCommitMsg(request *CommitMsg) {
	c.Commits = append(c.Commits, request)
}
