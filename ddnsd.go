package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	pb "github.com/dhtech/proto/dns"
	pbacme "github.com/bluecmd/cert-manager-proto"
	"github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"gopkg.in/yaml.v2"
)

var (
	serverCert       = flag.String("server_crt", "server.crt", "Server HTTPS certificate")
	serverKey        = flag.String("server_key", "server.key", "Server HTTPS certificate key")
	trustedClientCa  = flag.String("trusted_client_ca", "client_ca.crt", "Trusted client CA")
	listen           = flag.String("listen", "[::]:443", "Address to listen on GRPC")
	targetServer     = flag.String("target_server", "localhost:53", "Where to send DNS requests")
	authzConfigFile  = flag.String("authz_config", "authz.yml", "Authorization config")
	ddnsSecretFile   = flag.String("ddns_secret", "ddns.key.yml", "Key file to authenticate with")
)

type role struct {
	Regex        []string
	Type         []string
	MatchSubject pkix.Name `yaml:"match_subject"`
}

type authzConfig struct {
	Role []role
}

type ddnsSecret struct {
	Zone    string
	Private string
}

type dnsServer struct {
	config *authzConfig
	secret *ddnsSecret
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

func (s *dnsServer) dnsRemoveRequest(soa string, records []*pb.Record) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetUpdate(soa)
	rrs := []dns.RR{}
	for _, record := range records {
		rrtype, ok := dns.StringToType[record.Type]
		if !ok {
			return nil, fmt.Errorf("unknown type %s", record.Type)
		}
		class, _ := dns.StringToClass["ANY"]
		h := dns.RR_Header{Name: record.Domain, Rrtype: rrtype, Class: class, Ttl: 0}
		rr, err := dns.NewRR(h.String())
		if err != nil {
			return nil, err
		}

		log.Printf("Record: %v", record)
		log.Printf("RR: %v", rr)
		rrs = append(rrs, rr)
	}
	m.RemoveRRset(rrs)
	return m, nil
}

func listIsSubset(peer []string, of []string) bool {
	for _, x := range of {
		found := false
		for _, y := range peer {
			if y == x {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func pkixIsSubset(peer *pkix.Name, of *pkix.Name) bool {
	if of.CommonName != "" && of.CommonName != peer.CommonName {
		return false
	}
	if of.SerialNumber != "" && of.SerialNumber != peer.SerialNumber {
		return false
	}
	return (
		listIsSubset(peer.Country, of.Country) &&
		listIsSubset(peer.Organization, of.Organization) &&
		listIsSubset(peer.OrganizationalUnit, of.OrganizationalUnit) &&
		listIsSubset(peer.Locality, of.Locality) &&
		listIsSubset(peer.Province, of.Province) &&
		listIsSubset(peer.StreetAddress, of.StreetAddress) &&
		listIsSubset(peer.PostalCode, of.PostalCode))
}

func (s *dnsServer) authorizePeer(r *pb.Record, peer *pkix.Name) bool {
	for _, role := range s.config.Role {
		found := false
		for _, t := range role.Type {
			if strings.ToLower(t) == strings.ToLower(r.Type) {
				found = true
				break
			}
		}
		if !found {
			return false
		}

		found = false
		for _, regex := range role.Regex {
			m, err := regexp.MatchString(regex, r.Domain)
			if err != nil {
				log.Printf("Regex failure on %s: %v", regex, err)
				continue
			}
			if m {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if pkixIsSubset(peer, &role.MatchSubject) {
			log.Printf("Role matches: %v", role)
			return true
		}
	}
	return false
}

func (s *dnsServer) insertOrRemove(ctx context.Context, records []*pb.Record, insert bool) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("no peer information available")
	}
	ta := p.AuthInfo.(credentials.TLSInfo)

	var peer pkix.Name
	if len(ta.State.PeerCertificates) > 0 {
		cert := ta.State.PeerCertificates[0]
		peer = cert.Subject
		log.Printf("Request from peer: %v", peer)
	} else {
		log.Printf("Request from anonymous peer")
	}

	soaMap := make(map[string][]*pb.Record)

	// Group record requests per SOA
	m := new(dns.Msg)
	for _, record := range records {
		if !s.authorizePeer(record, &peer) {
			return fmt.Errorf("not authorized to execute %v", record)
		}
		m.SetQuestion(record.Domain, dns.TypeSOA)
		r, err := dns.Exchange(m, *targetServer)
		if err != nil {
			return err
		}
		if len(r.Ns) == 0 {
			return fmt.Errorf("did not receive any authority for %s", record.Domain)
		}
		soa, ok := r.Ns[0].(*dns.SOA)
		if !ok {
			return fmt.Errorf("did not receive SOA for %s", record.Domain)
		}
		log.Printf("SOA for %s: %s", record.Domain, soa.Hdr.Name)
		soaMap[soa.Hdr.Name] = append(soaMap[soa.Hdr.Name], record)
	}

	// Create all messages first to catch validation errors before committing anything.
	msgs := []*dns.Msg{}
	for soa, records := range soaMap {
		var m *dns.Msg
		var err error
		if insert {
			m, err = s.dnsInsertRequest(soa, records)
		} else {
			m, err = s.dnsRemoveRequest(soa, records)
		}
		if err != nil {
			return err
		}
		log.Printf("Assembled batch to SOA %s with %d records", soa, len(records))
		msgs = append(msgs, m)
	}

	// Commit. If there is an error, continue with other operations and return error in the end.
	c := &dns.Client{Net: "tcp"}
	c.TsigSecret = map[string]string{s.secret.Zone: s.secret.Private}
	errs := []error{}
	for _, m := range msgs {
		m.SetTsig(s.secret.Zone, dns.HmacSHA512, 300, time.Now().Unix())
		r, _, err := c.Exchange(m, *targetServer)
		if err != nil {
			log.Printf("failed to execute insert: %v", err)
			errs = append(errs, err)
		}
		if r.Rcode != dns.RcodeSuccess {
			log.Printf("operation returned %d", r.Rcode)
			errs = append(errs, fmt.Errorf("status %d", r.Rcode))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d operations failed", len(errs))
	}
	return nil
}

func (s *dnsServer) getZoneRecords(ctx context.Context, zone string) ([]*pb.Record, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return []*pb.Record{}, fmt.Errorf("no peer information available")
	}
	ta := p.AuthInfo.(credentials.TLSInfo)

	var peer pkix.Name
	if len(ta.State.PeerCertificates) > 0 {
		cert := ta.State.PeerCertificates[0]
		peer = cert.Subject
		log.Printf("Request from peer: %v", peer)
	} else {
		log.Printf("Request from anonymous peer")
	}

	if !s.authorizePeer(&pb.Record{Domain: zone, Type: "AXFR"}, &peer) {
		return []*pb.Record{}, fmt.Errorf("not authorized to transfer zone")
	}

	t := new(dns.Transfer)
	t.TsigSecret = map[string]string{s.secret.Zone: s.secret.Private}

	m := new(dns.Msg)
	m.SetAxfr(zone)
	m.SetTsig(s.secret.Zone, dns.HmacSHA512, 300, time.Now().Unix())
	c, err := t.In(m, *targetServer)
	if err != nil {
		return []*pb.Record{}, err
	}
	res := []*pb.Record{}
	for rrs := range c {
		if rrs.Error != nil {
			return []*pb.Record{}, rrs.Error
		}
		for _, r := range rrs.RR {
			hdr := r.Header()
			h := hdr.String()
			data := r.String()[len(h):]
			cls, ok := dns.ClassToString[hdr.Class]
			if !ok {
				log.Printf("Unknown class %v on %s, skipping record", hdr.Class, hdr.Name)
				continue
			}
			typ, ok := dns.TypeToString[hdr.Rrtype]
			if !ok {
				log.Printf("Unknown type %v on %s, skipping record", hdr.Rrtype, hdr.Name)
				continue
			}
			res = append(res, &pb.Record{
				Domain: hdr.Name,
				Ttl: hdr.Ttl,
				Class: cls,
				Type: typ,
				Data: data,
			})
		}
	}
	return res, nil
}

func (s *dnsServer) Insert(ctx context.Context, r *pb.InsertRequest) (*pb.InsertResponse, error) {
	err := s.insertOrRemove(ctx, r.Record, true)
	if err != nil {
		return nil, err
	}
	return &pb.InsertResponse{}, nil
}

func (s *dnsServer) Remove(ctx context.Context, r *pb.RemoveRequest) (*pb.RemoveResponse, error) {
	err := s.insertOrRemove(ctx, r.Record, false)
	if err != nil {
		return nil, err
	}
	return &pb.RemoveResponse{}, nil
}

func (s *dnsServer) GetZone(ctx context.Context, r *pb.GetZoneRequest) (*pb.GetZoneResponse, error) {
	records, err := s.getZoneRecords(ctx, r.Zone)
	if err != nil {
		return nil, err
	}
	return &pb.GetZoneResponse{Record: records}, nil
}

func (s *dnsServer) Present(ctx context.Context, r *pbacme.PresentRequest) (*pbacme.PresentResponse, error) {
	record := pb.Record{
		Domain: r.Fqdn,
		Ttl: r.Ttl,
		Class: "IN",
		Type: "TXT",
		Data: r.Value,
	}
	records := []*pb.Record{&record}
	err := s.insertOrRemove(ctx, records, true)
	if err != nil {
		return nil, err
	}
	return &pbacme.PresentResponse{}, nil
}

func (s *dnsServer) CleanUp(ctx context.Context, r *pbacme.CleanUpRequest) (*pbacme.CleanUpResponse, error) {
	record := pb.Record{
		Domain: r.Fqdn,
		Type: "TXT",
	}
	records := []*pb.Record{&record}
	err := s.insertOrRemove(ctx, records, false)
	if err != nil {
		return nil, err
	}
	return &pbacme.CleanUpResponse{}, nil
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

	s := dnsServer{}

	cbin, err := ioutil.ReadFile(os.ExpandEnv(*authzConfigFile))
	if err != nil {
		log.Fatalf("unable to load authz config: %v", err)
	}
	err = yaml.Unmarshal(cbin, &s.config)
	if err != nil {
		log.Fatalf("unable to parse authz config: %v", err)
	}

	sbin, err := ioutil.ReadFile(os.ExpandEnv(*ddnsSecretFile))
	if err != nil {
		log.Fatalf("unable to load ddns secret: %v", err)
	}
	err = yaml.Unmarshal(sbin, &s.secret)
	if err != nil {
		log.Fatalf("unable to parse ddns secret: %v", err)
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

	g := grpc.NewServer(grpc.Creds(ta))
	pb.RegisterDynamicDnsServiceServer(g, &s)
	pbacme.RegisterAcmeDnsSolverServiceServer(g, &s)
	reflection.Register(g)
	g.Serve(l)
}
