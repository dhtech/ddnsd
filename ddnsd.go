package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	// "google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	pb "github.com/dhtech/proto/dns"
)

var (
	serverCert       = flag.String("server_crt", "server.crt", "Server HTTPS certificate")
	serverKey        = flag.String("server_key", "server.key", "Server HTTPS certificate key")
	trustedClientCa  = flag.String("trusted_client_ca", "client_ca.crt", "Trusted client CA")
	listen           = flag.String("listen", "[::]:443", "Address to listen on GRPC")
	targetServer     = flag.String("target_server", "localhost:53", "Where to send DNS requests")
	authzConfig      = flag.String("authz_config", "authz.yml", "Authorization config")
	ddnsSecret       = flag.String("ddns_secret", "ddns.key", "Key file to authenticate with")
)

type dnsServer struct {
}

func (s *dnsServer) dnsInsertRequest(soa string, records []*pb.Record) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetUpdate(soa)
	rrs := []dns.RR{}
	for _, record := range records {
		rrtype, ok := dns.StringToType[record.Type]
		if !ok {
			return nil, fmt.Errorf("unknown type %s", record.Type)
		}
		class, ok := dns.StringToClass[record.Class]
		if !ok {
			return nil, fmt.Errorf("unknown class %s", record.Type)
		}

		h := dns.RR_Header{Name: record.Domain, Rrtype: rrtype, Class: class, Ttl: record.Ttl}
		rr, err := dns.NewRR(h.String() + " " + record.Data)
		if err != nil {
			return nil, err
		}

		log.Printf("Record: %v", record)
		log.Printf("RR: %v", rr)
		rrs = append(rrs, rr)
	}
	m.Insert(rrs)
	return m, nil
}

func (s *dnsServer) Insert(ctx context.Context, r *pb.InsertRequest) (*pb.InsertResponse, error) {
	soaMap := make(map[string][]*pb.Record)

	// Group record requests per SOA
	m := new(dns.Msg)
	for _, record := range r.Record {
		m.SetQuestion(record.Domain, dns.TypeSOA)
		r, err:= dns.Exchange(m, *targetServer)
		if err != nil {
			return nil, err
		}
		if len(r.Ns) == 0 {
			return nil, fmt.Errorf("did not receive any authority for %s", record.Domain)
		}
		soa, ok := r.Ns[0].(*dns.SOA)
		if !ok {
			return nil, fmt.Errorf("did not receive SOA for %s", record.Domain)
		}
		log.Printf("SOA for %s: %s", record.Domain, soa.Hdr.Name)
		soaMap[soa.Hdr.Name] = append(soaMap[soa.Hdr.Name], record)
	}

	// Create all messages first to catch validation errors before committing anything.
	msgs := []*dns.Msg{}
	for soa, records := range soaMap {
		m, err := s.dnsInsertRequest(soa, records)
		if err != nil {
			return nil, err
		}
		log.Printf("Assembled batch to SOA %s with %d records", soa, len(records))
		msgs = append(msgs, m)
	}

	// Commit. If there is an error, continue with other operations and return error in the end.
	c := &dns.Client{Net: "tcp"}
	errs := []error{}
	for _, m := range msgs {
		r, _, err := c.Exchange(m, *targetServer)
		if err != nil {
			log.Printf("failed to execute insert: %v", err)
			errs = append(errs, err)
		}
		if r.Opcode != dns.RcodeSuccess {
			log.Printf("operation returned %d", r.Opcode)
			errs = append(errs, fmt.Errorf("status %d", r.Opcode))
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%d operations failed", len(errs))
	}
	return &pb.InsertResponse{}, nil
}

func (s *dnsServer) Remove(ctx context.Context, r *pb.RemoveRequest) (*pb.RemoveResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func main() {
	flag.Parse()

	scert, err := tls.LoadX509KeyPair(os.ExpandEnv(*serverCert), os.ExpandEnv(*serverKey))
	if err != nil {
		log.Fatalf("unable to load server cert/key: %v", err)
	}
	clientCa, err := ioutil.ReadFile(os.ExpandEnv(*trustedClientCa))
	if err != nil {
		log.Fatalf("unable to load trusted client CA: %v", err)
	}

	capool := x509.NewCertPool()
	capool.AppendCertsFromPEM(clientCa)

	ta := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{scert},
		ClientCAs:    capool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	})

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("could not listen: %v", err)
	}

	s := dnsServer{}

	g := grpc.NewServer(grpc.Creds(ta))
	pb.RegisterDynamicDnsServiceServer(g, &s)
	reflection.Register(g)
	g.Serve(l)
}
