package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	pb "github.com/anxinzhou/LPBFT/pbft"
	"github.com/ethereum/go-ethereum/crypto"
	mt "github.com/txaty/go-merkletree"
	"google.golang.org/grpc"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	_ "net/http/pprof"
)

type Server struct {
	pbft *pb.PBFT
	pb.UnimplementedConsensusServer
}

type ServerConfig struct {
	Address []string `json:"address"`
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

func (s *Server) BatchPBFTMessaging(stream pb.Consensus_BatchPBFTMessagingServer) error {
	for {
		request, err := stream.Recv() // will it park go routine? Because so far seems the program get stuck
		if err == io.EOF {
			panic(err)
		}

		if err != nil {
			log.Fatalf("can not receive %v", err)
		}

		//log.Printf("receive a batch request with # %d", request.BatchNum)

		go s.pbft.BatchEventLoop(request)
	}
}

var (
	port           = flag.Int("port", 50000, "The server port")
	serverID       = flag.Int("id", 0, "The server identity")
	configFilePath = flag.String("config-file", "config/localServer.json", "config file")
	//ip       = flag.String("ip", "127.0.0.1", "The server address")
	//port = flag.String("address", "", "Server address e.g. 127.0.0.1:8080")
)

//var (
//	serverAddrs = []string{
//		"localhost:50000",
//		"localhost:50001",
//		"localhost:50002",
//		"localhost:50003",
//		//"localhost:50004",
//		//"localhost:50005",
//		//"localhost:50006",
//	}
//)

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

	log.Printf("sign time %s", time.Since(start))
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

type testData struct {
	data []byte
}

func (t *testData) Serialize() ([]byte, error) {
	return t.data, nil
}

// generate dummy data blocks
func generateRandBlocks(size int) (blocks []mt.DataBlock) {
	for i := 0; i < size; i++ {
		block := &testData{
			data: make([]byte, 100),
		}
		_, err := rand.Read(block.data)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return
}

func testBatchMerkle(sampleSize int, batchSize int) {

	start := time.Now()
	for i := 0; i < sampleSize/batchSize; i++ {
		blocks := generateRandBlocks(batchSize)
		// the first argument is config, if it is nil, then default config is adopted
		tree, err := mt.New(nil, blocks)
		if err != nil {
			panic(err)
		}
		// get proofs
		proofs := tree.Proofs
		rootHash := tree.Root

		log.Printf("root hash: %v", rootHash)

		//func() {
		//	tree, err := mt.New(nil, blocks)
		//	if err != nil {
		//		panic(err)
		//	}
		//	// get proofs
		//	rootHash := tree.Root
		//
		//	log.Printf("root hash2: %v", rootHash)
		//}()
		//
		//return

		blockIDtoTest := 0
		ok, err := mt.Verify(blocks[blockIDtoTest], proofs[blockIDtoTest], rootHash, nil)
		if err != nil {
			panic(err)
		}
		if !ok {
			panic("should be ok")
		}
	}

	log.Printf("verification time %s", time.Since(start))
}

// TODO A stream can be interrupted by a service or connection error. Logic is required to restart stream if there is an error.
func main() {
	// get config file
	log.Printf("avaible cpu %d", runtime.NumCPU())
	jsonFile, err := os.Open(*configFilePath)
	if err != nil {
		panic(err)
	}
	configByte, err := io.ReadAll(jsonFile)
	if err != nil {
		panic(err)
	}

	var config ServerConfig
	err = json.Unmarshal(configByte, &config)
	if err != nil {
		panic(err)
	}

	serverAddrs := config.Address
	// profiling
	//if *serverID == 0 {
	//	go func() {
	//		r := http.NewServeMux()
	//		r.HandleFunc("/debug/pprof/", pprof.Index)
	//		r.HandleFunc("/debug/pprof/heap", pprof.Index)
	//		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	//		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	//		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	//		r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	//		err := http.ListenAndServe(":10001", r)
	//		if err != nil {
	//			panic(err)
	//		}
	//	}()
	//}
	//log.Printf("avaible cpu %d", runtime.NumCPU())

	//testBatchMerkle(100000, 32)
	//return
	//testSignatureVerification(99996, 6)
	//return
	var wg sync.WaitGroup
	// start server program
	faultTolerance := 1 // 3f+1 f=1
	pbft := pb.NewPBFT(int32(*serverID), faultTolerance)
	pbftRPC := &Server{
		pbft: pbft,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		serve(pbftRPC)
	}()

	// wait for other server is up
	time.Sleep(200 * time.Millisecond)

	pbft.ConnectPeers(serverAddrs)

	// start sending queue if batch mode enabled
	if pb.MESSAGE_BATCH_ENABLED {
		go pbft.StartSendQueue()
	}

	// start send queue if batch enabled

	// wait so that peers are mutually connected.
	//time.Sleep(200 * time.Millisecond)

	clientNum := 4000
	clients := make([]*pb.FakeClient, clientNum)
	for i := 0; i < clientNum; i++ {
		clients[i] = pb.NewFakeClient(int32(*serverID))
	}

	msgs := make([]*pb.ClientMsg, clientNum)

	for i := 0; i < clientNum; i++ {
		// so far let the client appoint the primary...
		if i == clientNum/20 {
			log.Printf("fake client generated %d", i)
		}
		clientMsg := clients[i].MakeFakeRequest()
		msgs[i] = clientMsg
	}

	// wait for setup
	time.Sleep(1500 * time.Millisecond)

	pb.Start = time.Now()
	log.Printf("start time %s", time.Now().String())
	for i := 0; i < clientNum; i++ {
		pbft.BroadcastPreprepare(msgs[i])
	}
	// how to know when will the requests be finished
	wg.Wait()

	log.Printf("unexpected close")
}
