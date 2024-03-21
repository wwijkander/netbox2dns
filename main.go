// netbox2dns.go
package main

import (
	"bufio"
	"bytes"
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
	"reflect"
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
	dnsZone     = flag.String("dnszone", "", "Comma separated list of zones we are answering questions for")
	soaContact  = flag.String("soacontact", "", "Contact for SOA record, format 'user.example.com'")
	zoneServers = flag.String("zoneservers", "", "Comma separated list of what NS records should be set to")

	debug = flag.Bool("debug", false, "debug?")

	dnsZoneSlice     []string
	zoneServersSlice []string

	client = &http.Client{}

	paginationOffset = 0

	replyMapv4 = make(map[string]map[string]string)
	replyMapv6 = make(map[string]map[string]string)

	hostname, _    = os.Hostname()
	lastHostUpdate = time.Now().Unix()
	reflectRegion  string
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
	ID         int         `json:"id"`
	Name       string      `json:"name"`
	Slug       interface{} `json:"slug"`
	PrimaryIP  interface{} `json:"primary_ip"`
	PrimaryIP4 interface{} `json:"primary_ip4"`
	PrimaryIP6 interface{} `json:"primary_ip6"`
	Created    string      `json:"created"`
	//LastUpdated time.Time `json:"last_updated"`
}

// ordering matters
type RegionLookupResult struct {
	Errors []RegionLookupResultErrors `json:"errors"`
	Data   RegionLookupResultData     `json:"data"`
}

type RegionLookupResultErrors struct {
	Message string `json:"message"`
}

type RegionLookupResultData struct {
	DeviceList []RegionLookupResultDeviceList `json:"device_list"`
}
type RegionLookupResultDeviceList struct {
	Site RegionLookupResultSite `json:"site"`
}

type RegionLookupResultSite struct {
	Region any `json:"region"`
}

type RegionLookupResultRegion struct {
	Parent any    `json:"parent"`
	Slug   string `json:"slug"`
}

func unmarshalNetboxHosts(marshalledData NetboxResult, region string) {
	netboxHostname := strings.ToLower(marshalledData.Name)
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
	netboxRequestURL := *netboxURL + endpoint + "&has_primary_ip=True&limit=50&offset=" + strconv.Itoa(paginationOffset)
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
		paginationOffset += 50
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
		regions = append(regions, v.Slug.(string))
	}

	if reply.Next != nil {
		paginationOffset += 50
		initNetboxRegions()
	}

	return regions
}

func readStruct(val reflect.Value) {
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	for i := 0; i < val.NumField(); i++ {
		//fmt.Println(val.Type().Field(i).Type.Kind())
		f := val.Field(i)
		switch f.Kind() {
		case reflect.Struct:
			readStruct(f)
		case reflect.Slice:
			if val.Type().Field(i).Name == "DeviceList" && f.Len() != 1 {
				log.Println("Not the correct amount of records(1) received from GraphQL")
				break
			}
			for j := 0; j < f.Len(); j++ {
				readStruct(f.Index(j))
			}
		case reflect.Interface:
			if f.IsNil() {
				if val.Type().Field(i).Name == "Parent" {
					reflectRegion = val.Field(i + 1).String()
				}

			} else {
				//fmt.Println(reflect.TypeOf(f.Interface()).String())
				regionStruct, _ := f.Interface().(RegionLookupResultRegion)
				readStruct(reflect.ValueOf(regionStruct))
			}
		case reflect.String:
			if val.Type().Field(i).Name == "Message" {
				log.Printf("Error received from GraphQL: %s", val.Field(i).String())
			}
		}
	}
}

func hostnameToRegion(hostname string) string {
	netboxRequestURL := *netboxURL + "/graphql/"
	log.Println("translating hostname to region using GraphQL" + netboxRequestURL)

	graphQLQuery := []byte(`
	{
	"query":
	 query {
	  device_list(name: \"` + hostname + `\") {
	    name
	    site {
	      region {
		slug
		level
		parent {
		  slug
		  level
		  parent {
		    slug
		    level
		    parent {
		      slug
		      level
		      parent {
			slug
			level
			parent {
			  slug
			  level
			}
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
	}`)

	req, err := http.NewRequest("POST", netboxRequestURL, bytes.NewBuffer(graphQLQuery))
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

	var reply RegionLookupResult

	err = decoded.Decode(&reply)
	if err != nil {
		panic(err)
	}

	readStruct(reflect.ValueOf(reply))

	return reflectRegion
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
		unmarshalNetboxHosts(webhook.Data, hostnameToRegion(webhook.Data.Name))
		reflectRegion = ""
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
		qname, domainPart, _ := strings.Cut(strings.ToLower(query.Parameters.Qname), ".")
		region, _, _ := strings.Cut(domainPart, ".")

		v4IP := replyMapv4[region][qname]
		v6IP := replyMapv6[region][qname]

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
			Qtype: "SOA",
			Qname: query.Parameters.Qname,
			//Qname:   *dnsZone,
			Content: *zoneServers + ". " + *soaContact + ". " + strconv.FormatInt(lastHostUpdate, 10) + " 14400 3600 2419000 43200",
			TTL:     172800,
		}

		var ns []PowerDNSResult
		for _, v := range zoneServersSlice {
			ns = append(ns, PowerDNSResult{
				Qtype: "NS",
				Qname: query.Parameters.Qname,
				//Qname:   *dnsZone,
				Content: v + ".",
				TTL:     172800,
			})
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
			case slices.Contains(dnsZoneSlice, query.Parameters.Qname):
				// we arbitrarily decide that the zone apex doesn't get to have A/AAAA

				ns = append(ns, soa)
				unmarshalledReply = PowerDNSResponse{
					Result: ns,
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
			if slices.Contains(dnsZoneSlice, query.Parameters.Qname) {
				unmarshalledReply = PowerDNSResponse{
					Result: []PowerDNSResult{soa},
				}
			}
		case "NS":
			if slices.Contains(dnsZoneSlice, query.Parameters.Qname) {
				unmarshalledReply = PowerDNSResponse{
					Result: ns,
				}
			}
		default:
			log.Println("unsupported qtype " + query.Parameters.Qtype)
		}

		marshalledReply, err := json.Marshal(&unmarshalledReply)
		if err != nil {
			panic(err)
		}
		if *debug {
			log.Printf("%s", string(marshalledReply))
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
	dnsZoneSlice = strings.Split(*dnsZone, ",")
	zoneServersSlice = strings.Split(*zoneServers, ",")

	// fetch initial inventory of hostnames and IPs
	startTime := time.Now()
	for _, v := range initNetboxRegions() {
		replyMapv4[v] = make(map[string]string)
		replyMapv6[v] = make(map[string]string)
		initNetboxHosts("/api/dcim/devices/?region="+v, v)
		log.Println("Initialized records for region " + v)
		paginationOffset = 0
	}
	replyMapv4["vm"] = make(map[string]string)
	replyMapv6["vm"] = make(map[string]string)
	initNetboxHosts("/api/virtualization/virtual-machines/?", "vm")
	log.Println("Initialized records for VMs")
	paginationOffset = 0

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
