package tcp

import (
	"fmt"
	"go-remotecall/remotecall"
	"log"
	"net"
	"time"
)

type TCPClient struct {
	con    *net.TCPConn
	Err    chan error               // error channel
	Out    chan remotecall.RCPacket // packet channel
	server *net.TCPAddr
	cfg    *Config
}

type Config struct {
	Server string
	Rconpw string
}

func NewTCPClient(cfg *Config) *TCPClient {
	return &TCPClient{
		Err: make(chan error),
		Out: make(chan remotecall.RCPacket),
		cfg: cfg,
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

		//u.con.SetNoDelay(false)
		u.con.SetWriteBuffer(512)

		//u.con.SetReadDeadline(time.Now().Add(15 * time.Second)) // REMOVE

		// login
		newPacket := remotecall.NewRCHandshake()
		newPacket.Password = u.cfg.Rconpw
		u.Out <- newPacket

		// listen for incoming packets
		for {

			totalBytes, err := u.con.Read(buf[:])
			log.Printf("READ %d bytes\n", totalBytes)
			//log.Printf("%# x\n", buf)
			//u.con.SetReadDeadline(time.Now().Add(60 * time.Second)) // REMOVE
			if err != nil {
				u.Err <- err
				u.con.Close()
				time.Sleep(15 * time.Second)
				continue Reconnect
			}

			err = header.Unmarshal(buf[:4])
			if err == nil {
				packetType := buf[4:5][0]
				log.Printf("PACKET TYPE %d", packetType)
				switch {
				case packetType == 0x01:
					// RC Handshake Response
					packet := remotecall.NewRCHandshakeResponse()
					err := packet.Unmarshal(buf[:totalBytes])
					if err == nil {
						u.Err <- fmt.Errorf("%# x", buf[:totalBytes])
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
						u.Err <- fmt.Errorf("%# x", buf[:totalBytes])
						if packet.Result == 0x00 {
							u.Err <- fmt.Errorf("content length ok")
						} else if packet.Result == 0x01 {
							u.Err <- fmt.Errorf("content length too short")
							return
						} else if packet.Result == 0x02 {
							u.Err <- fmt.Errorf("content length too long")
							return
						} else if packet.Result == 0x03 {
							u.Err <- fmt.Errorf("already waiting for content")
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
