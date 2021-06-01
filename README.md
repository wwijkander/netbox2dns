# netbox2dns
(Hacky) PowerDNS backend for exposing NetBox hostnames with their management IPv4/IPv6s as DNS records, using the NetBox API.

Will probably break if you have a larger installation.

## Example PowerDNS configuration
```
setgid=pdns
setuid=pdns
loglevel=7
launch=remote
remote-connection-string=unix:path=/opt/netbox2dns/netbox2dns.socket
```

## NetBox configuration
* Go to the Netbox admin area
* Add read only token in Home › Users › Tokens
* Add a POST webhook in Home › Extras › Webhooks
  * (suggested) Content types: DCIM › device and Virtualization › virtual machine
  * Events: create, update and delete
  * URL: where netbox2dns is running on port 8053 using HTTPS and endpoint /v0/netboxHook, e.g. https://netbox-ns.example.com:8053/v0/netboxHook
  * HTTP method: POST
  * HTTP content type: application/json
  * Secret: set to the same as the API token you generated above
  * Enable SSL verification: on(specify your own trusted CA if needed)
* Test things out by starting netbox2dns with flags below set and and the webhook by adding a host with management IP while running

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
