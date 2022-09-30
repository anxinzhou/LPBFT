package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	pb "github.com/anxinzhou/LPBFT/pbft"
	"google.golang.org/grpc"
	"io"
	"log"
	"net"
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
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Fatalf("can not receive %v", err)
		}
		s.pbft.EventLoop(request)
	}
}

var (
	port     = flag.Int("port", 50001, "The server port")
	serverID = flag.Int("id", 0, "The server identity")
)

var (
	serverAddrs = []string{
		"localhost:50001",
		"localhost:50002",
		"localhost:50003",
		"localhost:50004",
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

func main() {
	var wg sync.WaitGroup
	// start server program
	faultTolerance := 1 // 3f+1 f=1
	pbft := pb.NewPBFT(*serverID, faultTolerance)
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

	clientNum := 100
	clients := make([]*pb.FakeClient, clientNum)
	for i := 1; i < clientNum; i++ {
		clients[i] = pb.NewFakeClient(*serverID)
	}
	log.Print(time.Now())
	for i := 1; i < clientNum; i++ {
		// so far let the client appoint the primary...
		log.Printf("fake client generated")
		clientMsg := clients[i].MakeFakeRequest()
		pbft.BroadcastPreprepare(clientMsg)
	}

	// how to know when will the requests be finished
	wg.Wait()
}
