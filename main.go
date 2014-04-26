package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/daviddengcn/go-colortext"
	"go-remotecall/remotecall"
	"go-remotecall/tcp"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

func main() {
	// json config
	configpath := flag.String("config", "default.json", "json config file")
	flag.Parse()
	*configpath = fmt.Sprintf("config/%s", *configpath)

	// json parse
	file, e := ioutil.ReadFile(*configpath)
	if e != nil {
		log.Fatalf("config error: %v\n", e)
		return
	}

	var config tcp.Config
	perr := json.Unmarshal(file, &config)
	if perr != nil {
		log.Fatalf("config error (%s): %s", *configpath, perr)
		return
	}

	client := tcp.NewTCPClient(&config)

	go client.ProcessPendingPackets()
	go client.Listen()
	go console(client)

	for {
		select {
		case e := <-client.Err:
			ct.ChangeColor(ct.Cyan, true, ct.Black, false)
			log.Println(e.Error())
			ct.ResetColor()
		}
	}
}

func console(t *tcp.TCPClient) {
	reader := bufio.NewReader(os.Stdin)

	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "login") {
			/*rawstr := strings.Fields(line)
			if len(rawstr) == 2 {
				newPacket := remotecall.NewRCHandshake()
				newPacket.Password = rawstr[1]
				t.Out <- newPacket
			}*/
		} else if strings.HasPrefix(line, "ql") {
			rawstr := strings.Fields(line)
			if len(rawstr) == 2 {
				newPacket := remotecall.NewRCQueryContentLength()
				i, err := strconv.Atoi(rawstr[1])
				if err != nil {
					t.Err <- err
				} else {
					newPacket.ContentLength = uint16(i)
					t.Out <- newPacket
				}
			}
		} else if strings.HasPrefix(line, "qc") {
			rawstr := strings.Fields(line)
			if len(rawstr) == 2 {
				newPacket := remotecall.NewRCQuery()
				newPacket.Content = rawstr[1]
				t.Out <- newPacket
			}
		} else if strings.HasPrefix(line, "qb") {
			rawstr := strings.Fields(line)
			if len(rawstr) == 2 {
				bytes, err := ioutil.ReadFile(rawstr[1])
				if err != nil {
					t.Err <- err
					return
				}
				content := string(bytes)

				byteToSend := len(content)
				iterations := math.Ceil(float64(byteToSend) / float64(507))

				log.Printf("bytesToSend: %d iterations: %f", byteToSend, iterations)
				it := int(iterations)

				newPacket1 := remotecall.NewRCQueryContentLength()
				newPacket1.ContentLength = uint16(byteToSend)
				t.Out <- newPacket1

				left, right := 0, 0
				for i := 1; i <= it; i++ {
					newPacket := remotecall.NewRCQuery()

					left = (i - 1) * 507
					right = (i * 507)

					if i == it {
						newPacket.Content = content[left:]
						//log.Printf("%d %s\n", i, content[left:])
					} else {
						newPacket.Content = content[left:right]
						//log.Printf("%d %s\n", i, content[left:right])
					}

					// debugging
					// func WriteFile(filename string, data []byte, perm os.FileMode) error
					//ioutil.WriteFile(fmt.Sprintf("packet_%i_", ...), data, perm)

					t.Out <- newPacket
				}
			}
		}
	}
}
