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
	buf := make([]byte, 4096)
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

		u.con.SetReadDeadline(time.Now().Add(15 * time.Second))

		// login
		newPacket := remotecall.NewRCHandshake()
		newPacket.Password = u.cfg.Rconpw
		u.Out <- newPacket

		// listen for incoming packets
		for {

			totalBytes, err := u.con.Read(buf[:])
			log.Printf("READ %d bytes\n", totalBytes)
			u.con.SetReadDeadline(time.Now().Add(60 * time.Second))
			if err != nil {
				u.Err <- err
				u.con.Close()
				continue Reconnect
			}

			err = header.Unmarshal(buf[:4])
			if err == nil {
				packetType := buf[4:5][0]
				log.Printf("%d", packetType)
				switch {
				case packetType == 0x01:
					// RC Server Handshake Response
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
				log.Printf("% #x\n", bytes)
				_, err := u.con.Write(bytes)
				if err != nil {
					u.Err <- err
				}
			} else {
				u.Err <- err
			}
		}
	}
}
