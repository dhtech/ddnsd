# ddnsd
Dynamic DNS (RFC 2136, e.g. bind9) daemon with gRPC

Exports the [DynamicDnsService](https://github.com/dhtech/proto/blob/master/dns/dns.proto) to allow mutal TLS authenticated DNS updates using regexp whitelisting.

Example usage:
```
./ddnsd -target_server=ns0.net.dreamhack.se:53
```
