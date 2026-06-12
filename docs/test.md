./p2p-vpn -mode relay -port 4001 -secret swarm.key -cluster my-vpn-cluster

/ip4/172.31.34.205/tcp/4001/p2p/QmP6uJKP236XreBBQLYc7JYkqtxWLimwe2T7JrFTVQVfc9

/ip4/98.83.233.254/tcp/4001/p2p/QmP6uJKP236XreBBQLYc7JYkqtxWLimwe2T7JrFTVQVfc9,/ip4/98.83.233.254/udp/4001/p2p/QmP6uJKP236XreBBQLYc7JYkqtxWLimwe2T7JrFTVQVfc9



sudo ./p2p-vpn -mode endpoint \
               -secret swarm.key \
               -cluster my-vpn-cluster \
               -datakey data.key \
               -relay "/ip4/98.83.233.254/tcp/4001/p2p/QmP6uJKP236XreBBQLYc7JYkqtxWLimwe2T7JrFTVQVfc9" \
               -tun-ip "10.200.0.1/24" \
               -advertise "192.168.56.0/24" \
               -identity identity-a.key

sudo ./p2p-vpn -mode endpoint \
               -secret swarm.key \
               -cluster my-vpn-cluster \
               -datakey data.key \
               -relay "/ip4/127.0.0.1/tcp/4001/p2p/QmP6uJKP236XreBBQLYc7JYkqtxWLimwe2T7JrFTVQVfc9" \
               -tun-ip "10.200.0.2/24" \
               -advertise "172.31.34.205/24" \
               -identity identity-b.key