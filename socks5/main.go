package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

// o  X'00' succeeded
// o  X'01' general SOCKS server failure
// o  X'02' connection not allowed by ruleset
// o  X'03' Network unreachable
// o  X'04' Host unreachable
// o  X'05' Connection refused
// o  X'06' TTL expired
// o  X'07' Command not supported
// o  X'08' Address type not supported
// o  X'09' to X'FF' unassigned
const (
	Succeeded = iota
	SocksError
	ConnectionNotAllowed
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddressNotSupported
)

//Socks5Server represents Socks5Server struct.
type Socks5Server struct {
	Version int
}

// Request represents client Request
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
//
// Where:
//
// o  VER    protocol version: X'05'
// o  CMD
//    o  CONNECT X'01'
//    o  BIND X'02'
//    o  UDP ASSOCIATE X'03'
// o  RSV    RESERVED
// o  ATYP   address type of following address
//    o  IP V4 address: X'01'
//    o  DOMAINNAME: X'03'
//    o  IP V6 address: X'04'
// o  DST.ADDR       desired destination address
// o  DST.PORT desired destination port in network octet
//    order
type Request struct {
	Version     byte
	Command     byte
	AddrType    byte
	IPV4Address []byte
	IPV6Address []byte
	Host        []byte
	Port        int
}

// Response represents response entity to client
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
type Response struct {
	Version   byte
	ReplyCode byte
	AddrType  byte
	AddrDest  []byte
	Port      []byte
}

// write writes response to client to reply request.
func (s *Socks5Server) write(conn net.Conn, resp *Response) error {
	b := []byte{
		resp.Version,
		resp.ReplyCode,
		0,
		resp.AddrType,
	}
	b = append(b, resp.AddrDest...)
	b = append(b, resp.Port...)
	fmt.Printf("buffer: %+v\n", b)
	_, err := conn.Write(b)
	return err
}

// error writes a failture to client.
func (s *Socks5Server) error(conn net.Conn, respCode byte) error {
	resp := &Response{
		Version:   byte(s.Version),
		ReplyCode: respCode,
		AddrType:  0x1,
		AddrDest:  []byte{0, 0, 0, 0},
		Port:      []byte{0, 0},
	}
	return s.write(conn, resp)
}

// proxy replay messages between tartget and conn
func (s *Socks5Server) proxy(dst io.Writer, src io.Reader, errCh chan error) error {
	fmt.Println("do proxying")
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	if closer, ok := dst.(*net.TCPConn); ok {
		closer.Close()
	}
	errCh <- err
	return err
}

// respond replies client response.
func (s *Socks5Server) respond(conn net.Conn, ip net.IP, port int) error {
	var addr []byte
	var addrType byte
	if ip.To4() != nil {
		addr = ip.To4()
		addrType = 0x1
	} else if ip.To16() != nil {
		addr = ip.To16()
		addrType = 0x4
	} else {
		return s.error(conn, AddressNotSupported)
	}
	resp := &Response{
		Version:   byte(s.Version),
		ReplyCode: Succeeded,
		AddrType:  addrType,
		AddrDest:  addr,
		Port:      []byte{byte(port << 8), byte(port & 0xff)},
	}
	log.Printf("response: %+v", resp)
	return s.write(conn, resp)
}

// connect connects server and target.
func (s *Socks5Server) connect(conn net.Conn, req *Request) error {
	fmt.Println("connecting")
	// set value to addr according appropriate field.
	var addr string
	if req.Host != nil {
		ip, err := net.ResolveIPAddr("ip", string(req.Host))
		if err != nil {
			return err
		}
		addr = ip.String()
	} else if req.IPV4Address != nil {
		addr = net.IPv4(
			req.IPV4Address[0],
			req.IPV4Address[1],
			req.IPV4Address[2],
			req.IPV4Address[3],
		).String()
	} else if req.IPV6Address != nil {
		addr = net.ParseIP(string(req.IPV6Address)).String()
	}
	// server and target
	target, err := net.Dial("tcp", net.JoinHostPort(addr, strconv.Itoa(req.Port)))
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return s.error(conn, byte(ConnectionRefused))
		} else if strings.Contains(err.Error(), "network is unreachable") {
			return s.error(conn, byte(NetworkUnreachable))
		}
	}
	defer target.Close()
	// ready to reply messages.
	local := target.LocalAddr().(*net.TCPAddr)
	// establish connection
	if err := s.respond(conn, local.IP, local.Port); err != nil {
		return err
	}

	// proxy
	errCh := make(chan error, 2)
	go s.proxy(target, conn, errCh)
	go s.proxy(conn, target, errCh)
	if err := <-errCh; err != nil {
		return err
	}
	if err := <-errCh; err != nil {
		return err
	}
	return nil
}

// request reply client it's replies.
func (s *Socks5Server) request(conn net.Conn, bReader *bufio.Reader) error {
	fmt.Println("handling request that contains the connect cmd or other cmd, it may be failed")
	header := make([]byte, 4)
	_, err := io.ReadAtLeast(bReader, header, 4)
	if err != nil {
		return err
	}

	// get request from client and encapsulate data.
	req := &Request{}
	req.Version = header[0]
	req.Command = header[1]
	req.AddrType = header[3]

	// judge addr type
	//o  X'01'
	//the address is a version-4 IP address, with a length of 4 octets
	//o  X'03'
	//the address field contains a fully-qualified domain name.  The first
	//octet of the address field contains the number of octets of name that
	//follow, there is no terminating NUL octet.
	//o  X'04'
	//the address is a version-6 IP address, with a length of 16 octets.
	addrLen := 0
	switch req.AddrType {
	case 0x1:
		addrLen = 4
	case 0x4:
		addrLen = 16
	case 0x3:
		length, err := bReader.ReadByte()
		if err != nil {
			return err
		}
		addrLen = int(length)
	}

	portSize := 2
	b := make([]byte, addrLen+portSize)
	_, err = io.ReadFull(bReader, b)
	if err != nil {
		return err
	}

	// parse addr and port
	switch req.AddrType {
	case 0x1:
		req.IPV4Address = b[:addrLen]
	case 0x4:
		req.IPV6Address = b[:addrLen]
	case 0x3:
		req.Host = b[:addrLen]
	}
	// network octet order -> big endian order
	// req.Port = int(binary.BigEndian.Uint16([]byte{b[addrLen]}))
	req.Port = int(b[addrLen])<<8 | int(b[addrLen+1])

	switch req.Command {
	case 0x1:
		// reply connect
		return s.connect(conn, req)
	default:
		return s.error(conn, byte(CommandNotSupported))
	}
}

// handleConnection connects between client and server
func (s *Socks5Server) handleConnection(conn net.Conn) error {
	fmt.Println("handle connection")
	bReader := bufio.NewReader(conn)
	version, err := bReader.ReadByte()
	if err != nil {
		return err
	}
	// check received VER field from client
	fmt.Println("received version from client is:", int(version))
	if int(version) != s.Version {
		return errors.New("version not supported")
	}
	authTypeCoun, err := bReader.ReadByte()
	if err != nil {
		return err
	}
	authType := make([]byte, authTypeCoun)
	_, err = io.ReadFull(bReader, authType)
	if err != nil {
		return err
	}

	// reply negociated method to client
	_, err = conn.Write([]byte{byte(s.Version), 0})
	if err != nil {
		return err
	}

	// ready to connection
	return s.request(conn, bReader)

}

// ListenAndServe creates a tcp listener.
func (s *Socks5Server) ListenAndServe(protocal, addr string) error {
	l, err := net.Listen(protocal, addr)
	if err != nil {
		return err
	}
	defer func() {
		log.Println("[DEBUG]listener closed.")
		l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		// handle connect
		go s.handleConnection(conn)
	}
	return nil
}
func main() {
	port := flag.Int("port", 7000, "port for proxy")
	flag.Parse()

	// new a Sockets5Server
	s := &Socks5Server{
		Version: 5,
	}

	err := s.ListenAndServe("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Socks5Server started error: %v", err)
	}
}
