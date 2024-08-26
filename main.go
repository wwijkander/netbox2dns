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

	"golang.org/x/exp/slices"
)

var (
	// flags
	pdnsSocket  = flag.String("pdnssocket", "", "Path to a socket where we talk with PowerDNS")
	trustedCA   = flag.String("trustedca", "", "Path to a file with CAs we trust for TLS to netbox")
	tlsCert     = flag.String("tlscert", "", "Path to a file with a TLS cert followed by chain for the webhook HTTPS listener")
	tlsKey      = flag.String("tlskey", "", "Path to a file with a TLS key for the webhook HTTPS listener")
	netboxURL   = flag.String("netboxurl", "", "Base URL where Netbox lives")
	netboxToken = flag.String("netboxtoken", "", "Netbox token")
	baseDomain  = flag.String("basedomain", "", "our base domain")
	soaContact  = flag.String("soacontact", "", "Contact for SOA record, format 'user.example.com'")
	zoneServers = flag.String("zoneservers", "", "Comma separated list of what NS records should be set to")

	debug            = flag.Bool("debug", false, "debug?")
	debugSkipSync    = flag.Bool("debug-skip-sync", false, "debug: skip initial sync?")
	debugSkipWebhook = flag.Bool("debug-skip-webhook", false, "debug: skip starting webhook?")

	dnsZoneSlice     []string
	zoneServersSlice []string

	client = &http.Client{}

	err error

	paginationOffset = 0

	replyMapv4 = make(map[string]map[string]string)
	replyMapv6 = make(map[string]map[string]string)
	regionMap  = make(map[string]string)

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
	//Result []PowerDNSResult `json:"result"`
	Result interface{} `json:"result"`
}

type PowerDNSResult struct {
	Qtype   string `json:"qtype"`
	Qname   string `json:"qname"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type PowerDNSResultGetAllDomains struct {
	ID             int      `json:"id"`
	Zone           string   `json:"zone"`
	Masters        []string `json:"masters"`
	NotifiedSerial int      `json:"notified_serial"`
	Serial         int      `json:"serial"`
	LastCheck      int      `json:"last_check"`
	Kind           string   `json:"kind"`
}

type InitNetboxReply struct {
	Count    int            `json:"count"`
	Next     interface{}    `json:"next"`
	Previous string         `json:"previous"`
	Results  []NetboxResult `json:"results"`
}

type UpdateNetboxHook struct {
	Event     string       `json:"event"`
	Timestamp string       `json:"timestamp"`
	Model     string       `json:"model"`
	Username  string       `json:"username"`
	RequestId string       `json:"request_id"`
	Data      NetboxResult `json:"data"`
}

type NetboxResult struct {
	ID         int           `json:"id"`
	Url        string        `json:"url"`
	Name       string        `json:"name"`
	Site       *NetboxResult `json:"site"`
	Region     interface{}   `json:"region"`
	Parent     *NetboxResult `json:"parent"`
	Slug       string        `json:"slug"`
	PrimaryIP4 interface{}   `json:"primary_ip4"`
	PrimaryIP6 interface{}   `json:"primary_ip6"`
	Created    string        `json:"created"`
	Depth      int           `json:"_depth"`
	//	PrimaryIP  interface{}  `json:"primary_ip"`
	//LastUpdated time.Time `json:"last_updated"`
}

func unmarshalNetboxHosts(marshalledData NetboxResult, region string) {
	if region == "" {
		log.Println("unmarshalNetboxHosts() dropping record with empty region")
		return
	}
	netboxHostname := strings.ToLower(marshalledData.Name)
	regionMap[netboxHostname] = region
	switch marshalledData.PrimaryIP4.(type) {
	case nil:
		//replyMapv4[netboxHostname] = ""
	default:
		primaryIPv4 := strings.Split(marshalledData.PrimaryIP4.(map[string]interface{})["address"].(string), "/")[0]
		replyMapv4[region][netboxHostname] = primaryIPv4
	}

	switch marshalledData.PrimaryIP6.(type) {
	case nil:
		//replyMapv6[netboxHostname] = ""
	default:
		primaryIPv6 := strings.Split(marshalledData.PrimaryIP6.(map[string]interface{})["address"].(string), "/")[0]
		replyMapv6[region][netboxHostname] = primaryIPv6
	}
}

func initNetboxHosts(endpoint string, region string) {
	netboxRequestURL := *netboxURL + endpoint + "&has_primary_ip=True&limit=1000&offset=" + strconv.Itoa(paginationOffset)
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
		unmarshalNetboxHosts(v, region)
	}

	if reply.Next != nil {
		paginationOffset += 1000
		initNetboxHosts(endpoint, region)
	}

	return
}

func initNetboxRegions() []string {
	netboxRequestURL := *netboxURL + "/api/dcim/regions/?parent=null&limit=50&offset=" + strconv.Itoa(paginationOffset)
	log.Println("Initialize Netbox regions from URL " + netboxRequestURL)
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

	var regions []string
	for _, v := range reply.Results {
		regions = append(regions, v.Slug)
	}

	if reply.Next != nil {
		paginationOffset += 50
		initNetboxRegions()
	}

	return regions
}

func netboxRequest(url string) NetboxResult {
	netboxRequestURL := *netboxURL + url

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

	var reply NetboxResult

	err = decoded.Decode(&reply)
	if err != nil {
		panic(err)
	}

	return reply
}

func siteToRegion(url string) string {

	region := ""

	reply := netboxRequest(url)

	i := reply.Region

	switch i.(type) {
	case nil:

	// TODO: fix below
	case map[string]interface{}:
		region = i.(map[string]interface{})["slug"].(string)
		regionID := int(i.(map[string]interface{})["id"].(float64))
		for depth := int(i.(map[string]interface{})["_depth"].(float64)); depth > 0; {
			url = "/api/dcim/regions/" + strconv.Itoa(regionID) + "/"
			reply := netboxRequest(url)

			region = reply.Parent.Slug
			regionID = reply.Parent.ID
			depth = reply.Parent.Depth
		}
	}

	return region
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
			log.Println("Dropping webhook update with weird JSON: \n" + string(hookBody))
		} else {

			switch webhook.Model {
			case "device":
				unmarshalNetboxHosts(webhook.Data, siteToRegion(webhook.Data.Site.Url))
				log.Println("Processed device webhook update")
			case "virtualmachine":
				unmarshalNetboxHosts(webhook.Data, "vm")
				log.Println("Processed VM webhook update")
			case "region":
				if webhook.Data.Depth == 0 {
					log.Println("Region layout in netbox may have changed. Consider revising DNS zone delegation and restarting this program with updated arguments!")
				}
			default:
				log.Println("Dropping webhook update with unknown model, you should probably check your netbox webhook settings: \n" + string(hookBody))
			}

			lastHostUpdate = time.Now().Unix()
		}
	default:
		log.Println("Dropping webhook update with bad HMAC!")
	}
}

func handleSocketQuery(content io.Reader) (string, error) {
	decoded := json.NewDecoder(content)

	var query PowerDNSQuery
	var unmarshalledReply PowerDNSResponse
	powerDNSResult := []PowerDNSResult{}

	err := decoded.Decode(&query)
	if err != nil {
		return "", err
	}

	switch query.Method {
	case "initialize":
		log.Println("initializing socket connection to PowerDNS")
		return `{"result":true}`, nil

	case "lookup":
		cleanQuery, found := strings.CutSuffix(strings.ToLower(query.Parameters.Qname), ".")
		if !found {
			log.Printf("Non-compliant qname received on socket")
			return `{"result":false}`, nil
		}

		qname, domainPart, _ := strings.Cut(cleanQuery, ".")

		region, _, _ := strings.Cut(domainPart, ".")

		v4IP := replyMapv4[region][qname]
		v6IP := replyMapv6[region][qname]
		var cnameRegion string
		if *baseDomain == domainPart && len(regionMap[qname]) > 0 {
			cnameRegion = qname + "." + regionMap[qname] + "." + *baseDomain + "."
		}

		a := PowerDNSResult{
			Qtype:   "A",
			Qname:   cleanQuery,
			Content: v4IP,
			TTL:     3600,
		}

		aaaa := PowerDNSResult{
			Qtype:   "AAAA",
			Qname:   cleanQuery,
			Content: v6IP,
			TTL:     3600,
		}

		cname := PowerDNSResult{
			Qtype:   "CNAME",
			Qname:   cleanQuery,
			Content: cnameRegion,
			TTL:     3600,
		}

		soa := PowerDNSResult{
			Qtype: "SOA",
			Qname: cleanQuery,
			//Qname:   *dnsZone,
			Content: zoneServersSlice[0] + ". " + *soaContact + ". " + strconv.FormatInt(lastHostUpdate, 10) + " 14400 3600 2419000 43200",
			TTL:     172800,
		}

		var ns []PowerDNSResult
		for _, v := range zoneServersSlice {
			ns = append(ns, PowerDNSResult{
				Qtype: "NS",
				Qname: cleanQuery,
				//Qname:   *dnsZone,
				Content: v + ".",
				TTL:     172800,
			})
		}

		switch query.Parameters.Qtype {
		case "A":
			if len(v4IP) > 0 {
				powerDNSResult = append(powerDNSResult, a)
			}
		case "AAAA":
			if len(v6IP) > 0 {
				powerDNSResult = append(powerDNSResult, aaaa)
			}
		case "CNAME":
			if len(cnameRegion) > 0 {
				powerDNSResult = append(powerDNSResult, cname)
			}
		case "ANY":
			switch {
			case slices.Contains(dnsZoneSlice, cleanQuery):
				// we arbitrarily decide that the zone apex doesn't get to have A/AAAA

				ns = append(ns, soa)
				powerDNSResult = ns
			case len(cnameRegion) > 0:
				powerDNSResult = append(powerDNSResult, cname)
			default:
				if len(v4IP) > 0 {
					powerDNSResult = append(powerDNSResult, a)
				}
				if len(v6IP) > 0 {
					powerDNSResult = append(powerDNSResult, aaaa)
				}
			}

		case "SOA":
			if slices.Contains(dnsZoneSlice, cleanQuery) {
				powerDNSResult = append(powerDNSResult, soa)
			}
		case "NS":
			if slices.Contains(dnsZoneSlice, cleanQuery) {
				powerDNSResult = ns
			}
		case "TXT":
			if qname == "netbox2dnsnetbox2dnsnetbox2dns" {
				txt := PowerDNSResult{
					Qtype:   "TXT",
					Qname:   cleanQuery,
					Content: "hello, txt",
					TTL:     42,
				}
				powerDNSResult = append(powerDNSResult, txt)
			}
		default:
			log.Println("Ignoring unsupported qtype " + query.Parameters.Qtype)
			return `{"result":false}`, nil
		}

		unmarshalledReply = PowerDNSResponse{
			Result: powerDNSResult,
		}

	// TODO axfr
	//case "list":
	// TODO dnssec
	//case "getBeforeAndAfterNamesAbsolute":

	case "getAllDomains":
		// PowerDNS zone cache support

		var gad []PowerDNSResultGetAllDomains

		for k, v := range dnsZoneSlice {
			gad = append(gad, PowerDNSResultGetAllDomains{
				ID:             k,
				Zone:           v + ".",
				Masters:        []string{},
				NotifiedSerial: -1,
				Serial:         0,
				LastCheck:      0,
				Kind:           "native",
			})
		}

		unmarshalledReply = PowerDNSResponse{
			Result: gad,
		}

	case "getAllDomainMetadata":
		// "You must always return something, if there are no values, you shall return empty set."
		unmarshalledReply = PowerDNSResponse{
			Result: []PowerDNSResult{},
		}

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
		log.Println("Ignoring unsupported query method " + query.Method)
		return `{"result":false}`, nil
	}

	marshalledReply, err := json.Marshal(&unmarshalledReply)
	if err != nil {
		panic(err)
	}

	return string(marshalledReply), nil
}

func handleSocketConnection(connection net.Conn) {
	defer connection.Close()
	log.Printf("Lookup socket client connected [%s]", connection.RemoteAddr().Network())
	scanner := bufio.NewScanner(connection)
	for scanner.Scan() {
		scanned := scanner.Text()

		if *debug {
			log.Println("DEBUG: read from socket: " + scanned)
		}

		socketOutput, err := handleSocketQuery(strings.NewReader(scanned))
		if err != nil {
			log.Println("error parsing JSON from socket: " + err.Error())
			continue
		}
		io.WriteString(connection, socketOutput)

		if *debug {
			log.Println("DEBUG: wrote to socket: " + socketOutput)
		}
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

	for _, v := range []*string{pdnsSocket, netboxURL, netboxToken, soaContact, zoneServers, baseDomain} {
		if len(*v) == 0 {
			log.Fatalln("ERROR: missing flag")
		}
	}
	zoneServersSlice = strings.Split(*zoneServers, ",")

	// fetch initial inventory of hostnames and IPs
	startTime := time.Now()
	for _, v := range initNetboxRegions() {
		dnsZoneSlice = append(dnsZoneSlice, v+"."+*baseDomain)
		replyMapv4[v] = make(map[string]string)
		replyMapv6[v] = make(map[string]string)
		if *debugSkipSync {
			log.Println("Skipped initialization for region " + v)
		} else {
			initNetboxHosts("/api/dcim/devices/?region="+v, v)
			log.Println("Initialized records for region " + v)
		}
		paginationOffset = 0
	}
	dnsZoneSlice = append(dnsZoneSlice, *baseDomain)
	replyMapv4["vm"] = make(map[string]string)
	replyMapv6["vm"] = make(map[string]string)
	if *debugSkipSync {
		log.Println("Skipped initialization for VMs")
	} else {
		initNetboxHosts("/api/virtualization/virtual-machines/?", "vm")
		log.Println("Initialized records for VMs")
	}
	paginationOffset = 0

	replyMapv6["debug"] = make(map[string]string)
	replyMapv6["debug"]["debug"] = "dead::"

	log.Printf("Done with initialization, took %s\n", time.Since(startTime))
	lastHostUpdate = time.Now().Unix()

	log.Println("starting with " + strconv.Itoa(len(replyMapv4)) + " A records")
	log.Println("starting with " + strconv.Itoa(len(replyMapv6)) + " AAAA records")

	if *debugSkipWebhook {
		log.Println("Not starting webhook handler goroutine")
	} else {
		mux := http.NewServeMux()
		mux.HandleFunc("/v0/netboxHook", hookHandler)
		// handle webhook updates in a goroutine to not block main()
		go func() {
			log.Fatal("update webhook error: " + http.ListenAndServeTLS(":8053", *tlsCert, *tlsKey, mux).Error())
		}()
	}

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
