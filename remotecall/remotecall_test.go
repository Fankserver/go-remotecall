package remotecall

import (
	"bytes"
	"testing"
)

const (
	PROTOCOL_VERSION = 0x01
)

func Test_NewRCHeader(t *testing.T) {
	testPkt := NewRCHeader()
	if string(testPkt.MagicBytes) != "RC" {
		t.Errorf("MagicBytes = \"%s\", want \"%s\"", testPkt.MagicBytes, []byte("RC"))
	}
	if testPkt.Version != PROTOCOL_VERSION {
		t.Errorf("Protocol version = %d, want %d", testPkt.Version, PROTOCOL_VERSION)
	}
	if testPkt.Spacer != 0xFF {
		t.Errorf("Spacer = %d, want %d", testPkt.Spacer, 0xFF)
	}
}

func Test_RCHeader_Unmarshal(t *testing.T) {
	testPkt := NewRCHeader()

	// reset
	testPkt.MagicBytes = []byte("NO")
	testPkt.Version = 0xFF
	testPkt.Spacer = 0x00

	err := testPkt.Unmarshal([]byte{0x52, 0x43, 0x01, 0xFF})
	if err != nil {
		t.Errorf("Error while unmarshalling: %s", err.Error())
	}
	if string(testPkt.MagicBytes) != "RC" {
		t.Errorf("MagicBytes = \"%s\", want \"%s\"", testPkt.MagicBytes, []byte("RC"))
	}
	if testPkt.Version != PROTOCOL_VERSION {
		t.Errorf("Protocol version = %d, want %d", testPkt.Version, PROTOCOL_VERSION)
	}
	if testPkt.Spacer != 0xFF {
		t.Errorf("Spacer = %d, want %d", testPkt.Spacer, 0xFF)
	}

	// test invalid packets
	err = testPkt.Unmarshal([]byte{0x52, 0x43, 0x01, 0xFF, 0xFF})
	if err == nil {
		t.Errorf("Did not return error: want \"%s\"", "invalid packet header: packet length mismatch (5)")
	}
	err = testPkt.Unmarshal([]byte{0x30, 0x31, 0x01, 0xFF})
	if err == nil {
		t.Errorf("Did not return error: want \"%s\"", "invalid packet header: magic bytes (01)")
	}
	err = testPkt.Unmarshal([]byte{0x30, 0x31, 0x01, 0x00})
	if err == nil {
		t.Errorf("Did not return error: want \"%s\"", "invalid packet header: spacer (0x00)")
	}
}

func Test_RCHeader_Marshal(t *testing.T) {
	testPkt := NewRCHeader()
	normBytes := []byte{0x52, 0x43, 0x01, 0xFF}

	testBytes, err := testPkt.Marshal()
	if err != nil {
		t.Errorf("Error while marshalling: %s", err.Error())
	}
	if !bytes.Equal(testBytes, normBytes) {
		t.Errorf("Byte slice mismatch: % #x, want % #x", testBytes, normBytes)
	}

	// test invalid packet
	testPkt.MagicBytes = []byte{0x00, 0x00, 0x00}
	testBytes, err = testPkt.Marshal()
	if err == nil {
		t.Errorf("Did not return error: want \"%s\"", "invalid packet header: packet length mismatch (5)")
	}
}

func Test_NewRCClientHandshake(t *testing.T) {
	testPkt := NewRCClientHandshake()

	if testPkt.PacketType != 0x00 {
		t.Errorf("PacketType = %d, want %d", testPkt.PacketType, 0x00)
	}
	if testPkt.Password != "default" {
		t.Errorf("Password = %s, want %s", testPkt.Password, "default")
	}
}

func Test_RCClientHandshake_Unmarshal(t *testing.T) {
	testPkt := NewRCClientHandshake()

	// reset
	testPkt.PacketType = 0xFF
	testPkt.Password = "retrogott"

	err := testPkt.Unmarshal([]byte{0x52, 0x43, 0x01, 0xFF, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74})
	if err != nil {
		t.Errorf("Error while unmarshalling: %s", err.Error())
	}
}

func Test_RCClientHandshake_Marshal(t *testing.T) {
	testPkt := NewRCClientHandshake()
	normBytes := []byte{0x52, 0x43, 0x01, 0xFF, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74}

	testBytes, err := testPkt.Marshal()
	if err != nil {
		t.Errorf("Error while marshalling: %s", err.Error())
	}
	if !bytes.Equal(testBytes, normBytes) {
		t.Errorf("Byte slice mismatch: % #x, want % #x", testBytes, normBytes)
	}

	// test invalid packet
	testPkt.Header.MagicBytes = []byte{0x00, 0x00, 0x00}
	testBytes, err = testPkt.Marshal()
	if err == nil {
		t.Errorf("Did not return error: want \"%s\"", "invalid packet header: packet length mismatch (5)")
	}
}

func Test_NewRCServerHandshake(t *testing.T) {
	testPkt := NewRCServerHandshake()

	if testPkt.PacketType != 0x01 {
		t.Errorf("PacketType = %d, want %d", testPkt.PacketType, 0x00)
	}
	if testPkt.Result != 0x00 {
		t.Errorf("Result = %#x, want %#x", testPkt.Result, 0)
	}
}

func Test_RCServerHandshake_Unmarshal(t *testing.T) {
	testPkt := NewRCServerHandshake()

	// reset
	testPkt.PacketType = 0xFF
	testPkt.Result = 0xFF

	err := testPkt.Unmarshal([]byte{0x52, 0x43, 0x01, 0xFF, 0x01, 0x00})
	if err != nil {
		t.Errorf("Error while unmarshalling: %s", err.Error())
	}
}
