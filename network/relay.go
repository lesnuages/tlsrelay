package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	ERR_COULD_NOT_DECODE    = 1 << iota
	ERR_HOST_UNREACHABLE    = iota
	ERR_BAD_FINGERPRINT     = iota
	ERR_KEY_GENERATION      = iota
	ERR_RAND_GENERATION     = iota
	ERR_CERT_CREATION       = iota
	ERR_MARSHAL_PRIVATE_KEY = iota
	ERR_X509_KEYPAIR        = iota
	ERR_LISTEN_FAILED       = iota
)

type TlsRelay struct {
	Remote net.Conn
	Lport  int
}

// Generates a self signed certificate, using the organization name
// from the established connection.
func GenerateCert(orgName string) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		os.Exit(ERR_KEY_GENERATION)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		os.Exit(ERR_RAND_GENERATION)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true,
		BasicConstraintsValid: true,
	}
	ifaces, err := net.InterfaceAddrs()
	for _, i := range ifaces {
		if ipnet, ok := i.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			template.IPAddresses = append(template.IPAddresses, ipnet.IP)
		}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		os.Exit(ERR_CERT_CREATION)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		os.Exit(ERR_MARSHAL_PRIVATE_KEY)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	certificate, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		os.Exit(ERR_X509_KEYPAIR)
	}
	return certificate
}

func (relay *TlsRelay) RelayStreams(conn net.Conn) {
	reader := io.TeeReader(conn, relay.Remote)
	printall := func(r io.Reader) {
		b, err := ioutil.ReadAll(r)
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Printf("% x", b)
	}
}

// NewRelay is used to create a new TlsRelay instance.
func NewRelay(port int) *TlsRelay {
	return &TlsRelay{Lport: port}
}

// Listen starts the listening server
func (relay *TlsRelay) Listen(orgName string) {
	cert := GenerateCert(orgName)
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(relay.Lport), config)
	if err != nil {
		log.Fatal("Could start listener")
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go relay.RelayStreams(conn)
	}
}

// Connect sets the connection to the remote server.
// The connection parameters are given in the connStr arg.
func (relay *TlsRelay) Connect(connStr string) {
	// Skip certificate verification
	config := &tls.Config{InsecureSkipVerify: true}
	if relay.Remote, err = tls.Dial("tcp", connStr, config); err != nil {
		log.Fatal("Could not connect to the remote host")
	}
}

func (relay *TlsRelay) Start(port int) {
	relay.Connect(strconv.Itoa(port))
}
