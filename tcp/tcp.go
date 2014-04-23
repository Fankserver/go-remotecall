package tcp

import (
	"fmt"
	"go-remotecall/remotecall"
	"log"
	"net"
	"sync"
	"time"
)

type TCPClient struct {
	con         *net.TCPConn
	Err         chan error               // error channel
	Out         chan remotecall.RCPacket // packet channel
	server      *net.TCPAddr
	online      bool
	onlineMutex *sync.Mutex
	cfg         *Config
}

type Config struct {
	Server string
	Rconpw string
}

func NewTCPClient(cfg *Config) *TCPClient {
	return &TCPClient{
		Err:         make(chan error),
		Out:         make(chan remotecall.RCPacket),
		onlineMutex: &sync.Mutex{},
		cfg:         cfg,
	}
}

func (u *TCPClient) Listen() {
	var buf [4096]byte
	var header remotecall.RCHeader

Reconnect:
	for {
		u.onlineMutex.Lock()
		u.online = true // todo: this is a hack... it should be false until proven
		u.onlineMutex.Unlock()

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
		newPacket := remotecall.NewRCClientHandshake()
		newPacket.Password = u.cfg.Rconpw
		u.Out <- newPacket

		// listen for incoming packets
		for {
			n, err := u.con.Read(buf[:])
			u.con.SetReadDeadline(time.Now().Add(60 * time.Second))
			u.onlineMutex.Lock()
			online := u.online
			if !online {
				err = fmt.Errorf("not online anymore")
			}
			u.onlineMutex.Unlock()
			if err != nil || !online {
				u.Err <- err
				u.con.Close()
				continue Reconnect
			} else {
				err = header.Unmarshal(buf[:n])
				if (err == nil) && (len(buf[:n]) >= 5) {
					packetType := buf[4:5][0]
					switch {
					case packetType == 0x00:
						// RC Server Handshake Response
						packet := remotecall.NewRCServerHandshake()
						err := packet.Unmarshal(buf[:n])
						if err == nil {
							if packet.Result == 0x00 {
								u.onlineMutex.Lock()
								u.online = true
								u.onlineMutex.Unlock()
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
}

func (u *TCPClient) ProcessPendingPackets() {
	for {
		select {
		case p := <-u.Out:
			log.Println("yolo")
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
