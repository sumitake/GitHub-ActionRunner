package main

import "net"

func requireLocalUnixPeerUID(
	connection *net.UnixConn,
	expectedUID uint32,
) error {
	peerUID, err := localUnixPeerUID(connection)
	if err != nil || peerUID != expectedUID {
		return errLocalProtocol
	}
	return nil
}
