#proto_include := $(shell go list -m -f {{.Dir}} github.com/relab/gorums):internal/proto
proto_src := pbft/pbft.proto          /
#		internal/proto/hotstuffpb/pbft.proto           \
		internal/proto/orchestrationpb/orchestration.proto \
		internal/proto/handelpb/handel.proto               \
		metrics/types/types.proto
proto_go := $(proto_src:%.proto=%.pb.go)
grpc_go := $(proto_src:%.proto=%_grpc.pb.go)
#gorums_go := internal/proto/clientpb/client_gorums.pb.go \
#		internal/proto/hotstuffpb/hotstuff_gorums.pb.go  \
#		internal/proto/handelpb/handel_gorums.pb.go

#binaries := pbft plot

export GOPATH := /home/anxin/go
export GOROOT := /usr/local/go

binaries := server

.PHONY: all debug clean protos download tools $(binaries)

all: $(binaries)
	#./p$(binaries)

debug: GCFLAGS += -gcflags='all=-N -l'
debug: $(binaries)
	#./p$(binaries)

$(binaries): protos
	go build -o ./p$@_linux $(GCFLAGS) ./$@

run: ./p$@_linux

build_and_run: debug run

protos: $(proto_go) $(gorums_go)

download:
	@go mod download

#tools: download
	@#cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -I % go install %

test:
	@go test -v ./...

#clean:
#	@rm -fv $(binaries)

%.pb.go %_grpc.pb.go : %.proto
	protoc --go_out=paths=source_relative:. \
		--go-grpc_out=paths=source_relative:. \
		$<


#protoc -I=.:$(proto_include) \
#		--go_out=paths=source_relative:. \
#		--go-grpc_out=paths=source_relative:. \
#		$<