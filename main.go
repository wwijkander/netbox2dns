// netbox2dns.go
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	// flags
	pdnsSocket  = flag.String("pdnssocket", "", "Path to a socket where we talk with PowerDNS")
	trustedCA   = flag.String("trustedca", "", "Path to a file with CAs we trust for TLS to netbox")
	tlsCert     = flag.String("tlscert", "", "Path to a file with a TLS cert followed by chain for the webhook HTTPS listener")
	tlsKey      = flag.String("tlskey", "", "Path to a file with a TLS key for the webhook HTTPS listener")
	netboxURL   = flag.String("netboxurl", "", "Base URL where Netbox lives")
	netboxToken = flag.String("netboxtoken", "", "Netbox token")
	dnsZone     = flag.String("dnszone", "", "Zone we are answering questions for")
	soaContact  = flag.String("soacontact", "", "Contact for SOA record, format 'user.example.com'")
	// TODO make this a comma separated list
	zoneServers = flag.String("zoneservers", "", "single(for now) FQDN that acts as DNS auth master for the zone")

	client = &http.Client{}

	paginationOffset = 0

	replyMapv4 = make(map[string]string)
	replyMapv6 = make(map[string]string)

	hostname, _    = os.Hostname()
	lastHostUpdate = time.Now().Unix()
)

type PowerDNSQuery struct {
	Method     string `json:"method"`
	Parameters struct {
		Local      string `json:"local"`
		Qname      string `json:"qname"`
		Qtype      string `json:"qtype"`
		RealRemote string `json:"real-remote"`
		Remote     string `json:"remote"`
		ZoneID     int    `json:"zone-id"`
		Path       string `json:"path"`
	} `json:"parameters"`
}

type PowerDNSResponse struct {
	Result []PowerDNSResult `json:"result"`
}

type PowerDNSResult struct {
	Qtype   string `json:"qtype"`
	Qname   string `json:"qname"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type InitNetboxReply struct {
	Count    int          `json:"count"`
	Next     interface{}  `json:"next"`
	Previous string       `json:"previous"`
	Results  []NetboxHost `json:"results"`
}
type UpdateNetboxHook struct {
	Event     string     `json:"event"`
	Timestamp string     `json:"timestamp"`
	Model     string     `json:"model"`
	Username  string     `json:"username"`
	RequestId string     `json:"request_id"`
	Data      NetboxHost `json:"data"`
}

type NetboxHost struct {
	ID         int         `json:"id"`
	Name       string      `json:"name"`
	PrimaryIP  interface{} `json:"primary_ip"`
	PrimaryIP4 interface{} `json:"primary_ip4"`
	PrimaryIP6 interface{} `json:"primary_ip6"`
	Created    string      `json:"created"`
	//LastUpdated time.Time `json:"last_updated"`
}

func unmarshalNetboxHosts(marshalledData NetboxHost) {
	netboxHostname := strings.ToLower(marshalledData.Name)
	switch marshalledData.PrimaryIP4.(type) {
	case nil:
		//replyMapv4[netboxHostname] = ""
	default:
		if len(replyMapv4[netboxHostname]) > 0 {
			log.Println("BUG: " + netboxHostname + " already has an IPv4 record, skipping!!!")
			return
		}
		primaryIPv4 := strings.Split(marshalledData.PrimaryIP4.(map[string]interface{})["address"].(string), "/")[0]
		replyMapv4[netboxHostname] = primaryIPv4
	}

	switch marshalledData.PrimaryIP6.(type) {
	case nil:
		//replyMapv6[netboxHostname] = ""
	default:
		if len(replyMapv6[netboxHostname]) > 0 {
			log.Println("BUG: " + netboxHostname + " already has an IPv6 record, skipping!!!")
			return
		}
		primaryIPv6 := strings.Split(marshalledData.PrimaryIP6.(map[string]interface{})["address"].(string), "/")[0]
		replyMapv6[netboxHostname] = primaryIPv6
	}
}

func initNetboxHosts(endpoint string) {
	netboxRequestURL := *netboxURL + endpoint + "?limit=50&offset=" + strconv.Itoa(paginationOffset)
	log.Println("Initialize Netbox Inventory from URL " + netboxRequestURL)
	req, err := http.NewRequest("GET", netboxRequestURL, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", "Token "+*netboxToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	decoded := json.NewDecoder(resp.Body)

	var reply InitNetboxReply

	err = decoded.Decode(&reply)
	if err != nil {
		panic(err)
	}
	for _, v := range reply.Results {
		unmarshalNetboxHosts(v)
	}

	if reply.Next != nil {
		paginationOffset += 50
		initNetboxHosts(endpoint)
	}

	return
}

func checkMAC(payload []byte, receivedMACStr string) bool {
	mac := hmac.New(sha512.New, []byte(*netboxToken))
	mac.Write(payload)
	calculatedMAC := mac.Sum(nil)

	receivedMAC, err := hex.DecodeString(receivedMACStr)
	if err != nil {
		log.Println("Error decoding HMAC hex: " + err.Error())
		return false
	}
	return hmac.Equal(receivedMAC, calculatedMAC)
}

func hookHandler(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	hookBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	switch req.Header["X-Hook-Signature"] != nil && checkMAC(hookBody, req.Header["X-Hook-Signature"][0]) {
	case true:

		var webhook UpdateNetboxHook

		err := json.Unmarshal(hookBody, &webhook)
		if err != nil {
			panic(err)
		}
		unmarshalNetboxHosts(webhook.Data)
		lastHostUpdate = time.Now().Unix()
		log.Println("Processed webhook from Netbox")
	default:
		log.Println("Dropping webhook update with bad HMAC!")
	}
}

func handleSocketQuery(content io.Reader) (string, error) {
	decoded := json.NewDecoder(content)

	var query PowerDNSQuery

	err := decoded.Decode(&query)
	if err != nil {
		return "", err
	}
	switch query.Method {
	case "initialize":
		log.Println("initializing socket connection to PowerDNS")
		return `{"result":true}`, nil

	case "lookup":
		qname := strings.TrimSuffix(query.Parameters.Qname, "."+*dnsZone+".")
		//log.Println("serving qtype " + query.Parameters.Qtype + " for qname " + query.Parameters.Qname + " to DNS client " + query.Parameters.Remote)

		v4IP := replyMapv4[strings.ToLower(qname)]
		v6IP := replyMapv6[strings.ToLower(qname)]

		a := PowerDNSResult{
			Qtype:   "A",
			Qname:   query.Parameters.Qname,
			Content: v4IP,
			TTL:     3600,
		}

		aaaa := PowerDNSResult{
			Qtype:   "AAAA",
			Qname:   query.Parameters.Qname,
			Content: v6IP,
			TTL:     3600,
		}

		soa := PowerDNSResult{
			Qtype:   "SOA",
			Qname:   *dnsZone,
			Content: *zoneServers + ". " + *soaContact + ". " + strconv.FormatInt(lastHostUpdate, 10) + " 14400 3600 2419000 43200",
			TTL:     172800,
		}

		ns := PowerDNSResult{
			Qtype:   "NS",
			Qname:   *dnsZone,
			Content: *zoneServers + ".",
			TTL:     172800,
		}

		unmarshalledReply := PowerDNSResponse{
			Result: []PowerDNSResult{},
		}

		// TODO this is ugly
		switch query.Parameters.Qtype {
		case "A":
			if len(v4IP) > 0 {
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{a},
				}
			}
		case "AAAA":
			if len(v6IP) > 0 {
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{aaaa},
				}
			}
		case "ANY":
			switch {
			case query.Parameters.Qname == *dnsZone+".":
				// we arbitrarily decide that the zone apex doesn't get to have A/AAAA
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{soa, ns},
				}
			case len(v4IP) > 0:
				switch {
				case len(v6IP) > 0:
					unmarshalledReply = PowerDNSResponse{
						Result: []PowerDNSResult{a, aaaa},
					}
				default:
					unmarshalledReply = PowerDNSResponse{
						Result: []PowerDNSResult{a},
					}
				}
			case len(v6IP) > 0:
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{aaaa},
				}
			}
		case "SOA":
			if query.Parameters.Qname == *dnsZone+"." {
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{soa},
				}
			}
		case "NS":
			if query.Parameters.Qname == *dnsZone+"." {
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{ns},
				}
			}
		default:
			log.Println("unsupported qtype " + query.Parameters.Qtype)
		}

		marshalledReply, err := json.Marshal(&unmarshalledReply)
		if err != nil {
			panic(err)
		}
		return string(marshalledReply), nil

	// TODO axfr
	//case "list":
	// TODO dnssec
	//case "getBeforeAndAfterNamesAbsolute":

	case "getAllDomainMetadata":
		// "You must always return something, if there are no values, you shall return empty set."
		unmarshalledReply := PowerDNSResponse{
			Result: []PowerDNSResult{},
		}

		marshalledReply, err := json.Marshal(&unmarshalledReply)
		if err != nil {
			panic(err)
		}

		return string(marshalledReply), nil

	//case "getDomainMetadata":
	//	return `{"result":false}`, nil
	//case "setDomainMetadata":
	//case "getDomainKeys":
	//case "addDomainKey":
	//case "removeDomainKey":
	//case "activateDomainKey":
	//case "deactivateDomainKey":
	//case "getTSIGKey":
	//case "getDomainInfo":

	default:
	}
	log.Println("ignoring unknown query method " + query.Method + " from PowerDNS")
	return `{"result":false}`, nil
}

func handleSocketConnection(connection net.Conn) {
	defer connection.Close()
	log.Printf("Lookup socket client connected [%s]", connection.RemoteAddr().Network())
	scanner := bufio.NewScanner(connection)
	for scanner.Scan() {
		// TODO unfuck this
		socketOutput, err := handleSocketQuery(strings.NewReader(scanner.Text()))
		if err != nil {
			log.Println("error parsing JSON from socket: " + err.Error())
			continue
		}
		io.WriteString(connection, socketOutput)
		//log.Println("DEBUG: wrote to socket: " + socketOutput)
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

func main() {
	flag.Parse()

	rootCAs := x509.NewCertPool()
	if len(*trustedCA) == 0 {
		rootCAs, _ = x509.SystemCertPool()
	} else {
		certs, err := ioutil.ReadFile(*trustedCA)
		if err != nil {
			log.Fatalln("ERROR: could not read CA file")
		}
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			log.Fatalln("ERROR: could not parse CA bundle")
		}
	}
	config := &tls.Config{
		RootCAs: rootCAs,
	}
	transport := &http.Transport{TLSClientConfig: config}
	client = &http.Client{Transport: transport}

	for _, v := range []*string{pdnsSocket, tlsCert, tlsKey, netboxURL, netboxToken, dnsZone, soaContact, zoneServers} {
		if len(*v) == 0 {
			log.Fatalln("ERROR: missing flag")
		}
	}

	// fetch initial inventory of hostnames and IPs
	startTime := time.Now()
	for _, v := range []string{"/api/dcim/devices/", "/api/virtualization/virtual-machines/"} {
		initNetboxHosts(v)
		log.Println("Initialized records for " + v)
		paginationOffset = 0
	}
	//initNetboxHosts([]string{"/api/dcim/devices/", "/api/virtualization/virtual-machines/"})
	log.Printf("Done with initialization, took %s\n", time.Since(startTime))
	lastHostUpdate = time.Now().Unix()

	log.Println("starting with " + strconv.Itoa(len(replyMapv4)) + " A records")
	log.Println("starting with " + strconv.Itoa(len(replyMapv6)) + " AAAA records")

	mux := http.NewServeMux()
	mux.HandleFunc("/v0/netboxHook", hookHandler)
	// handle webhook updates in a goroutine to not block main()
	go func() {
		log.Fatal("update webhook error: " + http.ListenAndServeTLS(":8053", *tlsCert, *tlsKey, mux).Error())
	}()

	if err := os.RemoveAll(*pdnsSocket); err != nil {
		log.Fatal(err)
	}

	unixSocket, err := net.Listen("unix", *pdnsSocket)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	defer unixSocket.Close()

	for {
		conn, err := unixSocket.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go handleSocketConnection(conn)
	}
}
