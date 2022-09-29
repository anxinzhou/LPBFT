package pbft

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

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

// collection of prepare
// used by the primary
type AggregatedPrepareMsg struct {
	InsID    *InstanceID
	ServerID int
	ViewNum  int
	//MsgDigest  []byte
}

type CommitMsg struct { // So far exactly the same as the prepareMsg
	InsID *InstanceID

	ServerID  int
	ViewNum   int
	Timestamp int
	//MsgDigest  []byte // Digest of a message, e.g., paymentMsg
}

type AggregatedCommitMsg struct {
	InsID *InstanceID

	ServerID int
	ViewNum  int
	//MsgDigest  []byte
}

func MakeFakeRequest() *ClientMsg {
	log.Printf("test2")
	// if is a primary
	//if *port == 50001 {
	log.Print("I am the primary")

	// Generate a key pair for the client
	clientPrivateKey, err := crypto.GenerateKey()

	if err != nil {
		log.Fatalf("Fail to generate private key for client")
	}

	// Simulate a payment message
	clientID := 1
	seqNum := 0

	paymentMsg := &PaymentMsg{
		InsID: &InstanceID{
			ClientPublicKey: &clientPrivateKey.PublicKey,
			SequenceNum:     seqNum,
		},
		UTXOIns: []UTXOInput{
			UTXOInput{
				PreviousTx: []byte("0x"),
				Loc:        0,
			},
		},
		UTXOuts: []UTXOutput{
			{
				ClientID: 1,
				Amount:   1,
			},
		},
	}
	payload, err := json.Marshal(paymentMsg)
	if err != nil {
		log.Fatalf("cannot marshal payload")
	}

	// sign the payload
	hash := crypto.Keccak256Hash(payload)
	signature, err := crypto.Sign(hash.Bytes(), clientPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	//clientPrivateKey.Sign()

	clientMsg := ClientMsg{
		MessageType: PAYMENT,
		InsID: &InstanceID{
			ClientPublicKey: &clientPrivateKey.PublicKey,
			SequenceNum:     seqNum,
		},
		Payload:   payload,
		Signature: signature,
	}

	return &clientMsg
}
