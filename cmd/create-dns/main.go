package main

import (
	"crypto/tls"
	"context"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/naming"
	pb "github.com/dhtech/proto/dns"
)

var (
	grpcService = flag.String("grpc", "dns.net.dreamhack.se", "Authentication server to use.")
	tlsUserCert = flag.String("tls_user_crt", "/var/lib/puppet/ssl/certs/$HOSTNAME.pem", "TLS client certificate to use")
	tlsUserKey  = flag.String("tls_user_key", "/var/lib/puppet/ssl/private_keys/HOSTNAME.pem", "TLS client certificate key to use")
	method      = flag.String("method", "insert", "Whether to insert or to remove a record")
)

func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(os.ExpandEnv(*tlsUserCert), os.ExpandEnv(*tlsUserKey))
	if err != nil {
		log.Fatalf("unable to load client certificate: %v", err)
	}

	d := grpc.WithTransportCredentials(
		credentials.NewTLS(&tls.Config{
			ServerName: *grpcService,
			Certificates: []tls.Certificate{cert},
		}),
	)

	// Discover the server
	resolver, err := naming.NewDNSResolver()
	if err != nil {
		log.Fatalf("unable to create resolver: %v", err)
	}

	watcher, err := resolver.Resolve(*grpcService)
	if err != nil {
		log.Fatalf("unable to resolve: %v", err)
	}

	targets, err := watcher.Next()
	if err != nil {
		log.Fatalf("unable to enumerate watcher: %v", err)
	}

	// Set up a connection to the server.
	var conn *grpc.ClientConn
	for _, target := range targets {
		var err error
		conn, err = grpc.Dial(target.Addr, d)
		if err != nil {
			log.Printf("could not connect to %s: %v", target.Addr, err)
			conn = nil
		}
		break
	}
	if conn == nil {
		log.Fatalf("no alive backends, cannot continue")
	}

	defer conn.Close()
	c := pb.NewDynamicDnsServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	textpb, err := ioutil.ReadAll(os.Stdin)

	if *method == "insert" {
		var req pb.InsertRequest
		err = proto.UnmarshalText(string(textpb), &req)
		if err != nil {
			log.Fatalf("unable to parse input: %v", err)
		}
		_, err = c.Insert(ctx, &req)
		if err != nil {
			log.Fatalf("could not process request: %v", err)
		}
	} else if *method == "remove" {
		var req pb.RemoveRequest
		err = proto.UnmarshalText(string(textpb), &req)
		if err != nil {
			log.Fatalf("unable to parse input: %v", err)
		}
		_, err = c.Remove(ctx, &req)
		if err != nil {
			log.Fatalf("could not process request: %v", err)
		}
	} else {
		log.Fatalf("unknown method: %s", *method)
	}
}
