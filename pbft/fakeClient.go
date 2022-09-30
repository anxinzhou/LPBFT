package pbft

import (
	"crypto/ecdsa"
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

type FakeClient struct {
	PublicKeyByte []byte
	privateKey    *ecdsa.PrivateKey
	SeqNum        int
	Primary       int
}

// so far let client appoint the primary
func NewFakeClient(primay int) *FakeClient {
	// Generate a key pair for the client
	privateKey, err := crypto.GenerateKey()

	if err != nil {
		log.Fatalf("Fail to generate private key for client")
	}

	// Simulate a payment message
	publicKeyByte := crypto.FromECDSAPub(&privateKey.PublicKey)
	return &FakeClient{
		PublicKeyByte: publicKeyByte,
		privateKey:    privateKey,
		SeqNum:        0,
		Primary:       primay,
	}
}

func (c *FakeClient) SignDataByte(data []byte) []byte {
	// sign the payload
	hash := crypto.Keccak256Hash(data)
	signature, err := crypto.Sign(hash.Bytes(), c.privateKey)
	if err != nil {
		panic(err)
	}
	return signature
}

func (c *FakeClient) MakeFakeRequest() *ClientMsg {

	paymentMsg := &PaymentMsg{
		InsID: &InstanceID{
			ClientPublicKeyByte: c.PublicKeyByte,
			SequenceNum:         c.SeqNum,
		},
		UTXOIns: []UTXOInput{
			{
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

	signature := c.SignDataByte(payload)

	clientMsg := ClientMsg{
		MessageType: PAYMENT,
		InsID: &InstanceID{
			ClientPublicKeyByte: c.PublicKeyByte,
			SequenceNum:         c.SeqNum,
		},
		Payload:   payload,
		Primary:   c.Primary,
		Signature: signature,
	}

	return &clientMsg
}
