package main

import (
	"errors"
	"golang.org/x/net/proxy"
	"log"
	"net"
)

type dummyDialer struct {

}

func (d dummyDialer) Dial(network, addr string) (c net.Conn, err error) {
	log.Println(network, addr)
	return nil, errors.New("not going to dial")
}

func main() {
	//dialer := dummyDialer{}
	proxyDialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, nil)
	if err != nil {
		log.Fatalln(err)
	}
	con, err := proxyDialer.Dial("tcp", "google.com:80")
	log.Println(con, err)
}
