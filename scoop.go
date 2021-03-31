package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
)

var names = map[string]uint16{
	"A":          dns.TypeA,
	"NS":         dns.TypeNS,
	"MD":         dns.TypeMD,
	"MF":         dns.TypeMF,
	"CNAME":      dns.TypeCNAME,
	"SOA":        dns.TypeSOA,
	"MB":         dns.TypeMB,
	"MG":         dns.TypeMG,
	"MR":         dns.TypeMR,
	"NULL":       dns.TypeNULL,
	"PTR":        dns.TypePTR,
	"HINFO":      dns.TypeHINFO,
	"MINFO":      dns.TypeMINFO,
	"MX":         dns.TypeMX,
	"TXT":        dns.TypeTXT,
	"RP":         dns.TypeRP,
	"AFSDB":      dns.TypeAFSDB,
	"X25":        dns.TypeX25,
	"ISDN":       dns.TypeISDN,
	"RT":         dns.TypeRT,
	"NSAPPTR":    dns.TypeNSAPPTR,
	"SIG":        dns.TypeSIG,
	"KEY":        dns.TypeKEY,
	"PX":         dns.TypePX,
	"GPOS":       dns.TypeGPOS,
	"AAAA":       dns.TypeAAAA,
	"LOC":        dns.TypeLOC,
	"NXT":        dns.TypeNXT,
	"EID":        dns.TypeEID,
	"NIMLOC":     dns.TypeNIMLOC,
	"SRV":        dns.TypeSRV,
	"ATMA":       dns.TypeATMA,
	"NAPTR":      dns.TypeNAPTR,
	"KX":         dns.TypeKX,
	"CERT":       dns.TypeCERT,
	"DNAME":      dns.TypeDNAME,
	"OPT":        dns.TypeOPT, // EDNS
	"APL":        dns.TypeAPL,
	"DS":         dns.TypeDS,
	"SSHFP":      dns.TypeSSHFP,
	"RRSIG":      dns.TypeRRSIG,
	"NSEC":       dns.TypeNSEC,
	"DNSKEY":     dns.TypeDNSKEY,
	"DHCID":      dns.TypeDHCID,
	"NSEC3":      dns.TypeNSEC3,
	"NSEC3PARAM": dns.TypeNSEC3PARAM,
	"TLSA":       dns.TypeTLSA,
	"SMIMEA":     dns.TypeSMIMEA,
	"HIP":        dns.TypeHIP,
	"NINFO":      dns.TypeNINFO,
	"RKEY":       dns.TypeRKEY,
	"TALINK":     dns.TypeTALINK,
	"CDS":        dns.TypeCDS,
	"CDNSKEY":    dns.TypeCDNSKEY,
	"OPENPGPKEY": dns.TypeOPENPGPKEY,
	"CSYNC":      dns.TypeCSYNC,
	"ZONEMD":     dns.TypeZONEMD,
	"SVCB":       dns.TypeSVCB,
	"HTTPS":      dns.TypeHTTPS,
	"SPF":        dns.TypeSPF,
	"UINFO":      dns.TypeUINFO,
	"UID":        dns.TypeUID,
	"GID":        dns.TypeGID,
	"UNSPEC":     dns.TypeUNSPEC,
	"NID":        dns.TypeNID,
	"L32":        dns.TypeL32,
	"L64":        dns.TypeL64,
	"LP":         dns.TypeLP,
	"EUI48":      dns.TypeEUI48,
	"EUI64":      dns.TypeEUI64,
	"URI":        dns.TypeURI,
	"CAA":        dns.TypeCAA,
	"AVC":        dns.TypeAVC,
	"TKEY":       dns.TypeTKEY,
	"TSIG":       dns.TypeTSIG,
	"IXFR":       dns.TypeIXFR,
	"AXFR":       dns.TypeAXFR,
	"MAILB":      dns.TypeMAILB,
	"MAILA":      dns.TypeMAILA,
	"ANY":        dns.TypeANY,
	"TA":         dns.TypeTA,
	"DLV":        dns.TypeDLV,
}

func GetDnsTypeFromName(name string) uint16 {
	return names[name]
}

func failArgs(format string, a ...interface{}) {
	outfile := os.Stderr
	_, _ = outfile.WriteString("ERROR: ")
	_, _ = fmt.Fprintf(outfile, format, a...)
	_, _ = outfile.WriteString("\n")
	os.Exit(1)
}

type DnsProtocol string

const (
	ProtocolTCP = DnsProtocol("tcp")
	ProtocolUDP = DnsProtocol("udp")
)

type ServerConfig struct {
	Protocol      DnsProtocol
	UseTLS        bool
	ServerHost    string
	ServerPort    string
	TlsServerName string
}

func (s ServerConfig) Address() string {
	return s.ServerHost + ":" + s.ServerPort
}

func (s ServerConfig) Network() string {
	return string(s.Protocol)
}

func parseServerArg(server string) (*ServerConfig, error) {
	var defaultPort = "53"
	var err error
	var result = new(ServerConfig)
	result.Protocol = "udp"
	var schemeEnd = strings.Index(server, "://")
	if schemeEnd > -1 {
		scheme := server[:schemeEnd]
		server = server[schemeEnd+3:]
		switch scheme {
		case "tls", "dot", "tcp-tls":
			result.Protocol = ProtocolTCP
			result.UseTLS = true
			defaultPort = "853"
		case "tcp":
			result.Protocol = ProtocolTCP
			defaultPort = "53"
		case "udp":
			result.Protocol = ProtocolUDP
			defaultPort = "53"
		default:
			return nil, fmt.Errorf("invalid scheme: %s", scheme)
		}
	}
	tlsNameIndex := strings.IndexByte(server, '#')
	if tlsNameIndex >= 0 {
		result.TlsServerName = server[tlsNameIndex+1:]
		server = server[:tlsNameIndex]
	}
	if len(server) == 0 {
		failArgs("got empty server")
	}
	result.ServerHost, result.ServerPort, err = net.SplitHostPort(server)
	if err != nil {
		addrError := err.(*net.AddrError)
		if addrError.Err == "missing port in address" {
			result.ServerPort = defaultPort
			result.ServerHost = server
		} else {
			return nil, fmt.Errorf("invalid server: %s", err)
		}
	}

	if result.Protocol == "" {
		switch result.ServerPort {
		case "853":
			result.Protocol = ProtocolTCP
			result.UseTLS = true
		default:
			fallthrough
		case "53":
			result.Protocol = ProtocolUDP
		}
	}
	return result, nil
}

func parseProxyArg(proxyValue string) (Dialer, error) {
	var proxyDialer Dialer
	proxyUrl, err := url.Parse(proxyValue)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %s", err)
	}
	proxyDialer, err = proxy.FromURL(proxyUrl, &net.Dialer{})
	if err != nil {
		return nil, fmt.Errorf("invalid proxy: %s", err)
	}
	return proxyDialer, nil
}

// A Dialer is a means to establish a connection.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type Scoop struct {
	Dialer Dialer
	TLSConfig *tls.Config
}

func (s Scoop) Exchange(server *ServerConfig, msg *dns.Msg) (*dns.Msg, error) {
	conn, err := s.Dial(server)
	if err != nil {
		return nil, err
	}
	err = conn.WriteMsg(msg)
	if err != nil {
		closeError := conn.Close()
		if closeError != nil {
			return nil, fmt.Errorf("failed to close connection: %s - after error %s", closeError, err)
		} else {
			return nil, err
		}
	}
	response, err := conn.ReadMsg()
	if err != nil {
		closeError := conn.Close()
		if closeError != nil {
			return nil, fmt.Errorf("failed to reaad connection: %s - after error %s", closeError, err)
		} else {
			return nil, err
		}
	}
	return response, conn.Close()
}

func (s Scoop) Dial(server *ServerConfig) (*dns.Conn, error) {
	var err error
	address := server.Address()
	network := server.Network()
	conn := new(dns.Conn)
	var dialer Dialer
	if s.Dialer == nil {
		dialer = &net.Dialer{}
	} else {
		dialer = s.Dialer
	}

	if server.UseTLS {
		var rawCon net.Conn
		var tlsConfig *tls.Config
		var tlsConn *tls.Conn
		if s.TLSConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = s.TLSConfig.Clone()
		}
		// Do not overwrite ServerName if specified in the tlsConfig already
		if tlsConfig.ServerName == "" {
			if server.TlsServerName != "" {
				tlsConfig.ServerName = server.ServerHost
			} else {
				tlsConfig.ServerName, _, err = net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
			}
		}
		rawCon, err = dialer.Dial(network, address)
		if err != nil {
			return nil, err
		}
		tlsConn = tls.Client(rawCon, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			return nil, err
		}
		conn.Conn = tlsConn
	} else {
		conn.Conn, err = dialer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}


func main() {
	var err error
	var dnsTypeName string
	var outputType string
	var name string
	var serverArg *ServerConfig
	var args = os.Args[1:]
	var proxyUrl string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) == 0 {
			failArgs("got empty argument")
		}
		if arg[0] == '-' {
			if len(arg) == 1 {
				failArgs("invalid argument '-'")
			} else if arg[1] == '-' {
				arg = arg[2:]
			} else {
				arg = arg[1:]
			}

			switch arg {
			case "tor":
				if proxyUrl != "" {
					failArgs("proxy already specified")
				}
				proxyUrl = "socks5h://127.0.0.1:9050"
				continue
			}

			var argValue string
			argParts := strings.SplitN(arg, "=", 2)
			if len(argParts) == 2 {
				arg = argParts[0]
				argValue = argParts[1]
			} else if i+1 == len(args) {
				failArgs("'%s' expects a value or is invalid flag", arg)
			} else {
				i++
				argValue = args[i]
			}
			switch arg {
			case "proxy":
				if proxyUrl != "" {
					failArgs("proxy already specified")
				}
				proxyUrl = argValue
			case "out":
				if outputType != "" {
					failArgs("'out' type already specified")
				}
				outputType = argValue
			default:
				failArgs("invalid argument: %s", arg)
			}
		} else if arg[0] == '@' {
			if serverArg != nil {
				failArgs("got multiple server")
			}
			serverArg, err = parseServerArg(arg[1:])
			if err != nil {
				failArgs(err.Error())
			}
		} else if names[arg] != dns.TypeNone {
			dnsTypeName = arg
		} else {
			if name != "" {
				failArgs("got multiple names: %s and %s", name, arg)
			}
			name = arg
		}
	}
	if name == "" {
		failArgs("got no name")
	}
	if serverArg == nil {
		if proxyUrl != "" {
			failArgs("server must be specified when using a proxy")
		}
		log.Println("got no server, using resolv.conf")
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			failArgs("failed to load resolv.conf: %s", err)
		}
		serverArg = new(ServerConfig)
		serverArg.ServerHost = config.Servers[0]
		serverArg.ServerPort = config.Port
		serverArg.Protocol = ProtocolUDP
	}
	log.Printf("using server %s on port %s \n", serverArg.ServerHost, serverArg.ServerPort)
	log.Printf("using network %s\n", serverArg.Network())
	if dnsTypeName == "" {
		var arpa string
		arpa, err = dns.ReverseAddr(name)
		if err != nil {
			dnsTypeName = "A"
		} else {
			name = arpa
			dnsTypeName = "PTR"
		}
	}
	dnsType := GetDnsTypeFromName(dnsTypeName)
	if dnsType == 0 {
		failArgs("invalid dns type: %s", dnsTypeName)
	}
	log.Printf("using dns type %s", dnsTypeName)

	scoop := new(Scoop)
	if proxyUrl != "" {
		scoop.Dialer, err = parseProxyArg(proxyUrl)
		if err != nil {
			failArgs(err.Error())
		}
		log.Printf("using proxy %s\n", proxyUrl)
	}
	if serverArg.TlsServerName == "" && isOnionAddress(serverArg.ServerHost) {
		log.Println("skipping TLS verification for .onion host")
		scoop.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else if serverArg.TlsServerName != "" {
		scoop.TLSConfig = &tls.Config{
			ServerName: serverArg.TlsServerName,
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dnsType)
	m.RecursionDesired = true

	response, err := scoop.Exchange(serverArg, m)
	if err != nil {
		fmt.Println(err)
		return
	}
	var writer DnsWriter = defaultWriter
	switch outputType {
	case "json":
		writer = &jsonWriter{
			Indent: "  ",
		}

	}
	err = writer.Write(os.Stdout, response)
	if err != nil {
		fmt.Println(" *** error:", err)
	}
}

type DnsWriter interface {
	Write(w io.Writer, answer *dns.Msg) error
}

type jsonWriter struct {
	Prefix string
	Indent string
}

func (writer jsonWriter) Write(w io.Writer, answer *dns.Msg) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent(writer.Prefix, writer.Indent)
	err := encoder.Encode(answer)
	return err
}

type writerFunc func(w io.Writer, answer *dns.Msg) error

func (fnc writerFunc) Write(w io.Writer, answer *dns.Msg) error {
	return fnc(w, answer)
}

var defaultWriter writerFunc = func(w io.Writer, answer *dns.Msg) (err error) {
	const (
		bold                  = "\033[1m"
		unbold                = "\033[0m"
		inlineFmt             = bold + "%-9s: " + unbold
		headerFmt             = bold + "\n> %s " + unbold + "\n"
		answerHighlightFormat = "\033[0;32m%v\u001B[0m\n"
		answerFailFormat      = "\033[0;31m%v\u001B[0m\n"
	)
	if _, err = fmt.Fprintf(w, inlineFmt+"%s (%d)\n", "Rcode", dns.RcodeToString[answer.Rcode], answer.Rcode); err != nil {
		return
	}
	if _, err = fmt.Fprintf(w, inlineFmt+"%d\n", "Id", answer.Id); err != nil {
		return
	}
	if _, err = fmt.Fprintf(w, inlineFmt+"%t\n", "Compress", answer.Compress); err != nil {
		return
	}
	if len(answer.Ns) > 0 {
		if _, err = fmt.Fprintf(w, headerFmt, "Nameservers"); err != nil {
			return
		}
		for _, nameserver := range answer.Ns {
			if _, err = fmt.Fprintf(w, "%v\n", nameserver); err != nil {
				return
			}
		}
	}
	if len(answer.Extra) > 0 {
		if _, err = fmt.Fprintf(w, headerFmt, "Extras"); err != nil {
			return
		}
		for _, extra := range answer.Extra {
			if _, err = fmt.Fprintf(w, "%v\n", extra); err != nil {
				return
			}
		}
	}

	if _, err = fmt.Fprintf(w, headerFmt, "Answers"); err != nil {
		return
	}
	if len(answer.Answer) == 0 {
		if _, err = fmt.Fprintf(w, answerFailFormat, "no answers"); err != nil {
			return
		}
	}
	for _, answer := range answer.Answer {
		if _, err = fmt.Fprintf(w, answerHighlightFormat, answer); err != nil {
			return
		}
	}
	return nil
}

func isOnionAddress(host string) bool {
	return strings.HasSuffix(host, ".onion")
}
