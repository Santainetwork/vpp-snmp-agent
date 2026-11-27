BINARY := vpp-snmp-agent
CMD := ./cmd/vpp-snmp-agent
BUILD_FLAGS := -trimpath -ldflags="-s -w"

.PHONY: build test install clean

build:
	go build $(BUILD_FLAGS) -o $(BINARY) $(CMD)

test:
	go test ./...

install:
	go install $(BUILD_FLAGS) $(CMD)

clean:
	rm -f $(BINARY)
