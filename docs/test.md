scp -i ~/.ssh/aws-rsa-again.pem p2p-vpn.linux-amd64 ec2-user@98.83.233.254:~/ 

./p2p-vpn -mode ca-keygen
openssl rand -hex 32 > data.key

# Print Relay Peer ID:
./p2p-vpn -mode relay -identity identity-relay.key
# Print Endpoint A Peer ID:
./p2p-vpn -mode endpoint -identity identity-a.key -dry-run
# Print Endpoint B Peer ID:
./p2p-vpn -mode endpoint -identity identity-b.key -dry-run

# Sign the Relay:
./p2p-vpn -mode ca-sign -ca-key-priv ca.key -peer <RELAY_PEER_ID>
# Sign Endpoint A:
./p2p-vpn -mode ca-sign -ca-key-priv ca.key -peer <ENDPOINT_A_PEER_ID>
# Sign Endpoint B:
./p2p-vpn -mode ca-sign -ca-key-priv ca.key -peer <ENDPOINT_B_PEER_ID>

cat <<EOF > whitelist.txt
<RELAY_PEER_ID>
<ENDPOINT_A_PEER_ID>
<ENDPOINT_B_PEER_ID>
EOF


./p2p-vpn -mode relay \
          -port 4001 \
          -cluster manual-test-cluster \
          -ca-key ca.pub \
          -node-sig identity-relay.sig
          # -allowed-peers whitelist.txt

./p2p-vpn -mode endpoint \
          -identity identity-a.key \
          -cluster manual-test-cluster \
          -datakey data.key \
          -relay "/ip4/127.0.0.1/tcp/4001/p2p/QmSjmaXTfZ11i6bC6E8JpAckL5corg1NW3BFcQAJvFBhVE" \
          -tun-ip "10.200.0.1/24" \
          -advertise "10.100.1.0/24" \
          -ca-key ca.pub \
          -node-sig identity-a.sig

./p2p-vpn -mode endpoint \
          -identity identity-b.key \
          -cluster manual-test-cluster \
          -datakey data.key \
          -relay "/ip4/127.0.0.1/tcp/4001/p2p/QmSjmaXTfZ11i6bC6E8JpAckL5corg1NW3BFcQAJvFBhVE" \
          -tun-ip "10.200.0.2/24" \
          -advertise "10.100.2.0/24" \
          -ca-key ca.pub \
          -node-sig identity-b.sig