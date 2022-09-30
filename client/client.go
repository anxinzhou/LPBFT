//package main
//
//import (
//	"crypto/ecdsa"
//	"encoding/json"
//	pb "github.com/anxinzhou/LPBFT/pbft"
//	"github.com/ethereum/go-ethereum/crypto"
//	"log"
//)
//
//type FakeClient struct {
//	PublicKeyByte []byte
//	privateKey    *ecdsa.PrivateKey
//	SeqNum        int
//	Primary       int
//}
//
//// so far let client appoint the primary
//func NewFakeClient(primay int) *FakeClient {
//	// Generate a key pair for the client
//	privateKey, err := crypto.GenerateKey()
//
//	if err != nil {
//		log.Fatalf("Fail to generate private key for client")
//	}
//
//	// Simulate a payment message
//	publicKeyByte := crypto.FromECDSAPub(&privateKey.PublicKey)
//	return &FakeClient{
//		PublicKeyByte: publicKeyByte,
//		privateKey:    privateKey,
//		SeqNum:        0,
//		Primary:       primay,
//	}
//}
//
//func (c *FakeClient) SignDataByte(data []byte) []byte {
//	// sign the payload
//	hash := crypto.Keccak256Hash(data)
//	signature, err := crypto.Sign(hash.Bytes(), c.privateKey)
//	if err != nil {
//		panic(err)
//	}
//	return signature
//}
//
//func (c *FakeClient) MakeFakeRequest() *pb.ClientMsg {
//	//log.Printf("test2")
//	// if is a primary
//	//if *port == 50001 {
//	log.Print("I am the primary")
//
//	paymentMsg := &pb.PaymentMsg{
//		InsID: &pb.InstanceID{
//			ClientPublicKeyByte: c.PublicKeyByte,
//			SequenceNum:         c.SeqNum,
//		},
//		UTXOIns: []pb.UTXOInput{
//			{
//				PreviousTx: []byte("0x"),
//				Loc:        0,
//			},
//		},
//		UTXOuts: []pb.UTXOutput{
//			{
//				ClientID: 1,
//				Amount:   1,
//			},
//		},
//	}
//	payload, err := json.Marshal(paymentMsg)
//	if err != nil {
//		log.Fatalf("cannot marshal payload")
//	}
//
//	signature := c.SignDataByte(payload)
//
//	clientMsg := pb.ClientMsg{
//		MessageType: pb.PAYMENT,
//		InsID: &pb.InstanceID{
//			ClientPublicKeyByte: c.PublicKeyByte,
//			SequenceNum:         c.SeqNum,
//		},
//		Payload:   payload,
//		Primary:   c.Primary,
//		Signature: signature,
//	}
//
//	return &clientMsg
//}
//
//func main() {
//	clientNum := 100
//	clients := make([]*pb.FakeClient, clientNum)
//	for i := 1; i < clientNum; i++ {
//		clients[i] = pb.NewFakeClient(*serverID)
//	}
//	for i := 1; i < 100; i++ {
//		// so far let the client appoint the primary...
//		log.Printf("fake client generated")
//		clientMsg := clients[i].MakeFakeRequest()
//		pbft.BroadcastPreprepare(clientMsg)
//	}
//}