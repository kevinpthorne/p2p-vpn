go build -o p2p-vpn.darwin-arm64
GOOS=windows GOARCH=amd64 go build -o p2p-vpn.win-amd64.exe
GOOS=linux GOARCH=amd64 go build -o p2p-vpn.linux-amd64
GOOS=linux GOARCH=arm64 go build -o p2p-vpn.linux-arm64