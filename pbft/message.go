package pbft

// client message type
const (
	PAYMENT int = 0
	OFF2ON
	ON2OFF
)

type UTXOInput struct {
	PreviousTx []byte
	Loc        int
}

type UTXOutput struct {
	ClientID int
	Amount   int
}

type PaymentMsg struct {
	InsID   *InstanceID
	UTXOIns []UTXOInput
	UTXOuts []UTXOutput
}

type ClientMsg struct {
	MessageType int
	InsID       *InstanceID
	Payload     []byte
	Primary     int32
	Signature   []byte // client's signature for the payload
}

type PreprerareMsg struct {
	InsID     *InstanceID
	ViewNum   int
	Timestamp int
	Msg       *ClientMsg
}

type PrepareMsg struct { //The backup must have received PreparePareMSg before
	InsID     *InstanceID
	ViewNum   int
	Timestamp int
	MsgDigest []byte
}

type Signature struct {
	Payload  []byte
	ServerID int32
}

type AggregatedPrepareMsg struct {
	InsID       *InstanceID
	PrepareMsgs []*PrepareMsg // 2f+1
	Signatures  []*Signature  // 2f+1
	Length      int
}

func (a *AggregatedPrepareMsg) appendPrepareMsg(prepareMsg *PrepareMsg, signature *Signature) {
	a.PrepareMsgs = append(a.PrepareMsgs, prepareMsg)
	a.Signatures = append(a.Signatures, signature)
	a.Length += 1
}

type CommitMsg struct { // So far exactly the same as the prepareMsg
	InsID     *InstanceID
	ViewNum   int
	Timestamp int
	MsgDigest []byte
}

type AggregatedCommitMsg struct {
	InsID      *InstanceID
	CommitMsgs []*CommitMsg // 2f+1
	Signatures []*Signature // 2f+1
	Length     int
}

func (a *AggregatedCommitMsg) AppendCommitMsg(commitMsg *CommitMsg, signature *Signature) {
	a.CommitMsgs = append(a.CommitMsgs, commitMsg)
	a.Signatures = append(a.Signatures, signature)
	a.Length += 1
}
