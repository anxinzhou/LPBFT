package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	pb "github.com/anxinzhou/LPBFT/pbft"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"time"
)

type Server struct {
	pbft *pb.PBFT
	pb.UnimplementedConsensusServer
}

func (s *Server) GetPublicKey(ctx context.Context, pkRequest *pb.PkRequest) (*pb.PkResponse, error) {
	return &pb.PkResponse{
		Payload: s.pbft.PublicKeyByte,
	}, nil
}

func (s *Server) ClientOperation(ctx context.Context, operationRequest *pb.OperationRequest) (*pb.OperationResponse, error) {
	var clientMsg pb.ClientMsg
	err := json.Unmarshal(operationRequest.Payload, &clientMsg)
	if err != nil {
		log.Fatalf("fail to marshal client request")
	}

	//completeStatus:= make(chan int)
	s.pbft.BroadcastPreprepare(&clientMsg)
	return nil, nil
	// TODO how to know when the request is done
}

func (s *Server) PBFTMessaging(stream pb.Consensus_PBFTMessagingServer) error {
	for {
		request, err := stream.Recv() // will it park go routine? Because so far seems the program get stuck
		if err == io.EOF {
			panic(err)
		}
		if err != nil {
			log.Fatalf("can not receive %v", err)
		}
		go s.pbft.EventLoop(request)
	}
}

var (
	port     = flag.Int("port", 50001, "The server port")
	serverID = flag.Int("id", 0, "The server identity")
)

var (
	serverAddrs = []string{
		"localhost:50000",
		"localhost:50001",
		"localhost:50002",
		"localhost:50003",
	}
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()
}

func serve(pbftRPC *Server) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterConsensusServer(s, pbftRPC)
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func testSignatureVerification(clientNum int, threadNum int) {
	clients := make([]*pb.FakeClient, clientNum)
	messageBytes := make([][]byte, clientNum)
	for i := 0; i < clientNum; i++ {
		clients[i] = pb.NewFakeClient(int32(*serverID))
		clientMsg := clients[i].MakeFakeRequest()
		dataByte, err := json.Marshal(clientMsg)
		if err != nil {
			panic(err)
		}
		messageBytes[i] = dataByte
	}
	// sign performance
	var wg sync.WaitGroup
	start := time.Now()
	sigs := make([][]byte, clientNum)
	batch := clientNum / threadNum
	if batch*threadNum != clientNum {
		panic(errors.New("task supposed to be equally dispathced"))
	}
	for k := 0; k < threadNum; k++ {
		wg.Add(1)
		threadIndex := k
		go func() {
			defer wg.Done()
			startClientNum := threadIndex * batch
			endClientNum := (threadIndex + 1) * batch
			for i := startClientNum; i < endClientNum; i++ {
				sig := clients[i].SignDataByte(messageBytes[i])
				sigs[i] = sig
			}
		}()
	}
	wg.Wait()

	log.Printf("time %s", time.Since(start))
	//verification performance
	start = time.Now()

	for k := 0; k < threadNum; k++ {
		wg.Add(1)
		threadIndex := k
		go func() {
			defer wg.Done()
			startClientNum := threadIndex * batch
			endClientNum := (threadIndex + 1) * batch
			for i := startClientNum; i < endClientNum; i++ {
				hash := crypto.Keccak256Hash(messageBytes[i])
				sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), sigs[i])
				if err != nil {
					panic(err)
				}
				if !bytes.Equal(sigPublicKey, clients[i].PublicKeyByte) {
					panic(errors.New("unmatch signature"))
				}
			}
		}()
	}
	wg.Wait()

	log.Printf("verify time %s", time.Since(start))
}

// TODO A stream can be interrupted by a service or connection error. Logic is required to restart stream if there is an error.
func main() {
	log.Printf("avaible cpu %d", runtime.NumCPU())
	//testSignatureVerification(99996, 6)
	//return
	var wg sync.WaitGroup
	// start server program
	faultTolerance := 1 // 3f+1 f=1
	pbft := pb.NewPBFT(int32(*serverID), faultTolerance)
	pbftRPC := &Server{
		pbft: pbft,
	}

	go func() {
		defer wg.Done()
		wg.Add(1)
		serve(pbftRPC)
	}()

	// wait so that all the servers are up
	time.Sleep(200 * time.Millisecond)

	pbft.ConnectPeers(serverAddrs)

	// wait so that peers are mutually connected.
	time.Sleep(200 * time.Millisecond)

	clientNum := 2000
	clients := make([]*pb.FakeClient, clientNum)
	for i := 0; i < clientNum; i++ {
		clients[i] = pb.NewFakeClient(int32(*serverID))
	}

	pb.Start = time.Now()
	log.Printf("start time %s", time.Now().String())
	for i := 0; i < clientNum; i++ {
		// so far let the client appoint the primary...
		if i == clientNum/20 {
			log.Printf("fake client generated %d", i)
		}
		clientMsg := clients[i].MakeFakeRequest()
		pbft.BroadcastPreprepare(clientMsg)
	}

	// how to know when will the requests be finished
	wg.Wait()
}
