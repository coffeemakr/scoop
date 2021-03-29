package main

import (
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
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

type serverArgs struct {
	Network    string
	ServerHost string
	ServerPort string
	TlsServerName string
}

func parseServerArg(server string) (*serverArgs, error) {
	var defaultPort = "53"
	var err error
	var result = new(serverArgs)
	var schemeEnd = strings.Index(server, "://")
	if schemeEnd > -1 {
		scheme := server[:schemeEnd]
		server = server[schemeEnd+3:]
		switch scheme {
		case "tls", "dot", "tcp-tls":
			result.Network = "tcp-tls"
			defaultPort = "853"
		case "tcp":
			result.Network = "tcp"
			defaultPort = "53"
		case "udp":
			result.Network = "udp"
			defaultPort = "53"
		default:
			return nil, fmt.Errorf("invalid scheme: %s", scheme)
		}
	}
	tlsNameIndex := strings.IndexByte(server, '#')
	if tlsNameIndex >= 0 {
		result.TlsServerName = server[tlsNameIndex + 1:]
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

	if result.Network == "" {
		switch result.ServerPort {
		case "853":
			result.Network = "tcp-tls"
		default:
			fallthrough
		case "53":
			result.Network = "udp"
		}
	}
	return result, nil
}

func parseProxyArg(proxyValue string) (dns.Dialer, error) {
	var proxyDialer dns.Dialer
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

func main() {
	var err error
	var dnsTypeName string
	var name string
	var serverArg *serverArgs
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
			} else if i + 1 == len(args) {
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
		serverArg = new(serverArgs)
		serverArg.ServerHost = config.Servers[0]
		serverArg.ServerPort = config.Port
	}
	log.Printf("using server %s on port %s \n", serverArg.ServerHost, serverArg.ServerPort)
	log.Printf("using network %s\n", serverArg.Network)
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

	client := new(dns.Client)
	if proxyUrl != "" {
		client.Dialer, err = parseProxyArg(proxyUrl)
		if err != nil {
			failArgs(err.Error())
		}
		log.Printf("using proxy %s\n", proxyUrl)
	}
	client.Net = serverArg.Network
	if serverArg.TlsServerName == "" && isOnionAddress(serverArg.ServerHost) {
		log.Println("skipping TLS verification for .onion host")
		client.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else if serverArg.TlsServerName != "" {
		client.TLSConfig = &tls.Config{
			ServerName: serverArg.TlsServerName,
		}
	}
 	err = Run(client, name, serverArg.ServerHost + ":" + serverArg.ServerPort, dnsType)
	if err != nil {
		fmt.Println(" *** error:", err)
	}
}

func isOnionAddress(host string) bool {
	return strings.HasSuffix(host, ".onion")
}

func Run(c *dns.Client, fqdn, server string, dnsType uint16) (err error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dnsType)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return fmt.Errorf("query failed: %s", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("answer not successfull: %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) == 0 {
		return fmt.Errorf("no answers")
	}
	// Stuff must be in the answer section
	for _, a := range r.Answer {
		fmt.Printf("%v\n", a)
	}
	return nil
}
