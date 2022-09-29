package main

import (
	"context"
	"crypto/elliptic"
	"flag"
	"fmt"
	pb "github.com/anxinzhou/LPBFT/pbft"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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
	pk := s.pbft.PublicKey()
	payload := elliptic.Marshal(secp256k1.S256(), pk.X, pk.Y)
	return &pb.PkResponse{
		Payload: payload,
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
		s.pbft.BackupEventLoop(stream, request)
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
	go pbft.PrimaryEventLoop()

	// if is primary
	if *port == 50001 {
		clientMsg := pb.MakeFakeRequest()
		pbft.BroadcastPreprepare(clientMsg)
	}
	wg.Wait()
}
