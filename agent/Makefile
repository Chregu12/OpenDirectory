BINARY_NAME  := od-agent
VERSION      := 1.0.0
BUILD_DIR    := dist
LDFLAGS      := -ldflags "-X main.version=$(VERSION) -s -w"
CMD_PATH     := ./cmd/od-agent

.PHONY: all deps linux windows macos clean install-linux

all: deps linux windows macos

deps:
	go mod tidy
	go mod download

linux: $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64   $(CMD_PATH)
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64   $(CMD_PATH)

windows: $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)

macos: $(BUILD_DIR)
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64  $(CMD_PATH)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64  $(CMD_PATH)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

install-linux: linux
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 /usr/local/bin/od-agent
	mkdir -p /etc/opendirectory
	@echo "Installed od-agent to /usr/local/bin/od-agent"
