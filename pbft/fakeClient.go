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
}

func NewFakeClient() *FakeClient {
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
	log.Printf("test2")
	// if is a primary
	//if *port == 50001 {
	log.Print("I am the primary")

	paymentMsg := &PaymentMsg{
		InsID: &InstanceID{
			ClientPublicKeyByte: c.PublicKeyByte,
			SequenceNum:         c.SeqNum,
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

	signature := c.SignDataByte(payload)

	clientMsg := ClientMsg{
		MessageType: PAYMENT,
		InsID: &InstanceID{
			ClientPublicKeyByte: c.PublicKeyByte,
			SequenceNum:         c.SeqNum,
		},
		Payload:   payload,
		Signature: signature,
	}

	return &clientMsg
}
