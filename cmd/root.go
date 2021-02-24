package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)
var rootCmd = &cobra.Command{
	Use:   "SSHFake",
	Short: "SSHFake short",
	Long: `SSHFake long`,
	Run: run,
}

var rsaFile string
var addr string

func Execute() {
	rootCmd.Flags().StringVar(&rsaFile, "rsa", "", "ssh rsa private key file. if don't specify this, it will generate a private key.")
	rootCmd.Flags().StringVar(&addr, "addr", "0.0.0.0:22", "the address that ssh listened. ex. SSHFake --addr 0.0.0.0:22")
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("user: %s, password: %s, client info: %s, remote address: %s.", c.User(), string(pass), string(c.ClientVersion()), c.RemoteAddr().String())
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	var privateBytes []byte
	if rsaFile == "" {
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			log.Fatal(err)
		}
		derStream := x509.MarshalPKCS1PrivateKey(privateKey)
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derStream,
		}
		privateBytes = pem.EncodeToMemory(block)
	} else {
		var err error
		privateBytes, err = ioutil.ReadFile(rsaFile)
		if err != nil {
			log.Fatal("Failed to load private key: ", err)
		}
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Println("failed to accept incoming connection: ", err)
			continue
		}
		ssh.NewServerConn(nConn, config)
	}
}