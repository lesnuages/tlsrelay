package main

import (
	"flag"

	"github.com/lesnuages/tlsrelay/network"
)

func main() {
	port := flag.Int("port", 8989, "Listening port")
	flag.Parse()
	relay := network.NewRelay(*port)
}
