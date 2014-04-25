package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/daviddengcn/go-colortext"
	"go-remotecall/tcp"
	"io/ioutil"
	"log"
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

	for {
		select {
		case e := <-client.Err:
			ct.ChangeColor(ct.Cyan, true, ct.Black, false)
			log.Println(e.Error())
			ct.ResetColor()
		}
	}
}
