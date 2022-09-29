package main

import (
	"context"
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

func (s *Server) GetPublicKey(ctx context.Context, pkrequest *pb.PkRequest) (*pb.PkResponse, error) {
	return &pb.PkResponse{
		Payload: s.pbft.PublicKeyByte,
	}, nil
}

func (s *Server) CStream(stream pb.Consensus_CStreamServer) error {
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Fatalf("can not receive %v", err)
		}
		s.pbft.EventLoop(stream, request)
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

	// wait for a second so that all the servers are up
	time.Sleep(200 * time.Millisecond)

	go func() {
		defer wg.Done()
		wg.Add(1)
		serve(pbftRPC)
	}()

	pbft.ConnectPeers(serverAddrs)

	//TODO so far different server will generate different fake client
	fakeClient := pb.NewFakeClient()
	// if is primary
	primary := pbft.PrimaryOfClient(fakeClient.PublicKeyByte)
	log.Printf("The primary of the fake client is %d", primary)
	// assign client to a fixed primary
	if *serverID == primary {
		clientMsg := fakeClient.MakeFakeRequest()
		pbft.BroadcastPreprepare(clientMsg)
	}
	wg.Wait()
}
