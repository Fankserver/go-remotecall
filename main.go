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
				go t.SendContent(&content)
			}
		} else if strings.HasPrefix(line, "cc") {
			line, _ := reader.ReadString('\n')

			go t.SendContent(&line)
		}
	}
}
