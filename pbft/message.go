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
	Signature   []byte // client's signature for the payload
}

type PreprerareMsg struct {
	InsID *InstanceID

	PrimaryID int
	ViewNum   int
	Timestamp int
	Msg       *ClientMsg
}

type PrepareMsg struct { //The backup must have received PreparePareMSg before
	InsID    *InstanceID
	ServerID int
	ViewNum  int
	//Timestamp  int
	//MsgDigest []byte // Digest of a message's payload, e.g., paymentMsg
}

type CommitMsg struct { // So far exactly the same as the prepareMsg
	InsID *InstanceID

	ServerID  int
	ViewNum   int
	Timestamp int
	//MsgDigest  []byte // Digest of a message, e.g., paymentMsg
}
