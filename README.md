# netbox2dns
PowerDNS backend for exposing NetBox hostnames with their management IPs as DNS records

## Configuration flags
`--netboxtoken` API Token for NetBox, also need to be set as HMAC secret

`--netboxurl` base URL where NetBox is reachable, e.g. https://netbox.example.com

`--trustedca` (optional) Path to CA to trust when verifying the Netbox TLS certificate, used *instead* of the default OS trust store

`--dnszone` the zone that we are serving labels under, e.g. mgmt.example.com

`--soacontact` a contact in SOA format, e.g. bob.example.com

`--zoneservers` a *single* DNS authoritative server (TODO: make this into a comma separated list) e.g. netbox-ns.example.com

`--tlscert` Path to a file containing TLS cert to present on webhook followed by CA chain

`--tlskey` Path to the key for above webhook certificate

`--pdnssocket` Path to a socket where PowerDNS is set up to talk with us, e.g. /opt/netbox2dns/netbox2dns.socket

## example PowerDNS configuration
```
setgid=pdns
setuid=pdns
loglevel=7
launch=remote
remote-connection-string=unix:path=/opt/netbox2dns/netbox2dns.socket
```
