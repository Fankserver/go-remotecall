package tcp

import (
	"fmt"
	"go-remotecall/remotecall"
	//"log"
	"math"
	"net"
	"time"
)

type TCPClient struct {
	con             *net.TCPConn
	Err             chan error               // error channel
	Out             chan remotecall.RCPacket // packet channel
	ContentResponse chan error               // content query channel
	server          *net.TCPAddr
	cfg             *Config
}

type Config struct {
	Server string
	Rconpw string
}

func NewTCPClient(cfg *Config) *TCPClient {
	return &TCPClient{
		Err:             make(chan error, 10),
		Out:             make(chan remotecall.RCPacket, 20),
		ContentResponse: make(chan error),
		cfg:             cfg,
	}
}

func (u *TCPClient) Listen() {
	buf := make([]byte, 1024)
	var header remotecall.RCHeader

Reconnect:
	for {
		// (re)connect
		server, err := net.ResolveTCPAddr("tcp", u.cfg.Server)
		if err != nil {
			u.Err <- err
			return
		}
		u.server = server

		u.con, err = net.DialTCP("tcp", nil, u.server)
		if err != nil {
			u.Err <- err
			time.Sleep(15 * time.Second)
			continue
		}

		u.con.SetWriteBuffer(1024)
		u.con.SetReadBuffer(1024)
		//u.con.SetKeepAlive(true)
		//u.con.SetKeepAlivePeriod(30 * time.Second)

		u.con.SetReadDeadline(time.Now().Add(15 * time.Second))

		// login
		newPacket := remotecall.NewRCHandshake()
		newPacket.Password = u.cfg.Rconpw
		u.Out <- newPacket

		// listen for incoming packets
		for {

			totalBytes, err := u.con.Read(buf[:])
			//log.Printf("READ %d bytes\n", totalBytes)
			//log.Printf("%# x\n", buf)
			u.con.SetReadDeadline(time.Now().Add(300 * time.Second))
			if err != nil {
				u.Err <- err
				u.con.Close()
				time.Sleep(15 * time.Second)
				continue Reconnect
			}

			err = header.Unmarshal(buf[:4])
			if err == nil {
				packetType := buf[4:5][0]
				//log.Printf("PACKET TYPE %d", packetType)
				switch {
				case packetType == 0x01:
					// RC Handshake Response
					packet := remotecall.NewRCHandshakeResponse()
					err := packet.Unmarshal(buf[:totalBytes])
					if err == nil {
						//u.Err <- fmt.Errorf("%# x", buf[:totalBytes])
						if packet.Result == 0x00 {
							u.Err <- fmt.Errorf("logged in")
						} else if packet.Result == 0x01 {
							u.Err <- fmt.Errorf("invalid password")
							return
						} else if packet.Result == 0x02 {
							u.Err <- fmt.Errorf("wrong version")
							return
						}
					}
				case packetType == 0x11:
					// RC Query Content Length Response
					packet := remotecall.NewRCContentLengthResponse()
					err := packet.Unmarshal(buf[:totalBytes])
					if err == nil {
						//u.Err <- fmt.Errorf("%# x", buf[:totalBytes])
						if packet.Result == 0x00 {
							u.ContentResponse <- nil // content length ok
						} else if packet.Result == 0x01 {
							u.ContentResponse <- fmt.Errorf("content length too short")
							return
						} else if packet.Result == 0x02 {
							u.ContentResponse <- fmt.Errorf("content length too long")
							return
						} else if packet.Result == 0x03 {
							u.ContentResponse <- fmt.Errorf("already waiting for content")
							return
						} else {
							u.ContentResponse <- fmt.Errorf("unknown error")
							return
						}
					}
				case packetType == 0x13:
					// RC Query Response
					packet := remotecall.NewRCQueryResponse()
					err := packet.Unmarshal(buf[:totalBytes])
					if err == nil {
						u.Err <- fmt.Errorf("%# x", buf[:totalBytes])
						u.Err <- fmt.Errorf("Query ID: %d", packet.QueryID)
					}
				}
			}
		}
	}
}

func (u *TCPClient) ProcessPendingPackets() {
	for {
		select {
		case p := <-u.Out:
			bytes, err := p.Marshal()
			if err == nil {
				//log.Printf("% #x\n", bytes)
				_, err := u.con.Write(bytes)
				if err != nil {
					u.Err <- err
				}
				//log.Printf("Sent %d byte\n", n)
			} else {
				u.Err <- err
			}
		}
	}
}

func (t *TCPClient) SendContent(c string) {
	content := c
	contentLength := len(content)
	iterations := math.Ceil(float64(contentLength) / float64(1024-5))
	it := int(iterations)

	//log.Printf("%d %f %d", contentLength, iterations, it)

	// query content length
	// and wait for response
	clQuery := remotecall.NewRCQueryContentLength()
	clQuery.ContentLength = uint16(contentLength)
	t.Out <- clQuery

	select {
	case err := <-t.ContentResponse:
		if err != nil {
			t.Err <- err
			return
		}
		/*case <-time.After(10 * time.Second):
		// timeout
		t.Err <- fmt.Errorf("no query length response received for 10 seconds")
		return*/
	}

	left, right := 0, 0
	for i := 1; i <= it; i++ {
		newPacket := remotecall.NewRCQuery()

		left = (i - 1) * (1024 - 5)
		right = (i * (1024 - 5))

		if i == it {
			newPacket.Content = content[left:]
			//log.Printf("%d %s\n", i, content[left:])
		} else {
			newPacket.Content = content[left:right]
			//log.Printf("%d %s\n", i, content[left:right])
		}
		//log.Printf("%s\n", newPacket.Content)
		t.Out <- newPacket
	}
}
