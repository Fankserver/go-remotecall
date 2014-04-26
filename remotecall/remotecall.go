package remotecall

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type RCPacket interface {
	Unmarshal(rawBytes []byte) error
	Marshal() ([]byte, error)
}

type RCHeader struct {
	MagicBytes []byte
	Version    byte
	Spacer     byte
}

func NewRCHeader() *RCHeader {
	return &RCHeader{MagicBytes: []byte("RC"), Version: 0x01, Spacer: 0xFF}
}

func (n *RCHeader) Unmarshal(rawBytes []byte) error {
	length := len(rawBytes)
	if length != 4 {
		return fmt.Errorf("invalid packet header: packet length mismatch (%d)", length)
	}
	n.MagicBytes = rawBytes[:2]
	if !bytes.Equal(n.MagicBytes, []byte("RC")) {
		return fmt.Errorf("invalid packet header: magic bytes (%s)", n.MagicBytes)
	}
	n.Version = rawBytes[2:3][0]
	n.Spacer = rawBytes[3:4][0]
	if n.Spacer != 0xFF {
		return fmt.Errorf("invalid packet header: spacer (%#x)", n.Spacer)
	}
	return nil
}

func (b *RCHeader) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	n, _ := buf.Write(b.MagicBytes)
	length += n
	buf.WriteByte(b.Version)
	length++
	buf.WriteByte(b.Spacer)
	length++
	if length != 4 {
		return nil, fmt.Errorf("invalid packet header: packet length mismatch (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCHandshake struct {
	Header     RCHeader
	PacketType byte
	Password   string
}

func NewRCHandshake() *RCHandshake {
	var packet RCHandshake
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x00
	packet.Password = ""
	return &packet
}

func (b *RCHandshake) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Password = string(rawBytes[5:])
	return nil
}

func (b *RCHandshake) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	n, _ = buf.WriteString(b.Password)
	length += n
	if length != (5 + len(b.Password)) {
		return nil, fmt.Errorf("invalid packet: packet length mismatch (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCHandshakeResponse struct {
	Header     RCHeader
	PacketType byte
	Result     byte
}

func NewRCHandshakeResponse() *RCHandshakeResponse {
	var packet RCHandshakeResponse
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x01
	packet.Result = 0x00
	return &packet
}

func (b *RCHandshakeResponse) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Result = rawBytes[5:6][0]
	return nil
}

func (b *RCHandshakeResponse) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	buf.WriteByte(b.Result)
	length += 1
	if length != 6 {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCQueryContentLength struct {
	Header        RCHeader
	PacketType    byte
	ContentLength uint16
}

func NewRCQueryContentLength() *RCQueryContentLength {
	var packet RCQueryContentLength
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x10
	packet.ContentLength = 0
	return &packet
}

func (b *RCQueryContentLength) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.ContentLength = binary.LittleEndian.Uint16(rawBytes[5:7])
	return nil
}

func (b *RCQueryContentLength) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, b.ContentLength)
	n, err = buf.Write(tmp)
	length += n
	if length != 7 {
		return nil, fmt.Errorf("invalid packet: packet length mismatch (%d) (%# x)", length, buf.Bytes())
	}
	return buf.Bytes(), nil
}

type RCContentLengthResponse struct {
	Header     RCHeader
	PacketType byte
	Result     byte
}

func NewRCContentLengthResponse() *RCContentLengthResponse {
	var packet RCContentLengthResponse
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x11
	packet.Result = 0x00
	return &packet
}

func (b *RCContentLengthResponse) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Result = rawBytes[5:6][0]
	return nil
}

func (b *RCContentLengthResponse) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	buf.WriteByte(b.Result)
	length += 1
	if length != 6 {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCQuery struct {
	Header     RCHeader
	PacketType byte
	Content    string
}

func NewRCQuery() *RCQuery {
	var packet RCQuery
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x12
	packet.Content = ""
	return &packet
}

func (b *RCQuery) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Content = string(rawBytes[5:])
	return nil
}

func (b *RCQuery) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	n, _ = buf.WriteString(b.Content)
	length += n
	if length != (5 + len(b.Content)) {
		return nil, fmt.Errorf("invalid packet: packet length mismatch (%d) (%# x) (%d)", length, buf.Bytes(), len(b.Content))
	}
	return buf.Bytes(), nil
}

type RCQueryResponse struct {
	Header     RCHeader
	PacketType byte
	QueryID    uint16
}

func NewRCQueryResponse() *RCQueryResponse {
	var packet RCQueryResponse
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x13
	packet.QueryID = 0
	return &packet
}

func (b *RCQueryResponse) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.QueryID = binary.LittleEndian.Uint16(rawBytes[5:7])
	return nil
}

func (b *RCQueryResponse) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, b.QueryID)
	length += n
	if length != 7 {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCQueryResultResponse struct {
	Header     RCHeader
	PacketType byte
	QueryID    uint16
	Content    string
}

func NewRCQueryResultResponse() *RCQueryResultResponse {
	var packet RCQueryResultResponse
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x14
	packet.QueryID = 0
	packet.Content = ""
	return &packet
}

func (b *RCQueryResultResponse) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.QueryID = binary.LittleEndian.Uint16(rawBytes[5:7])
	b.Content = string(rawBytes[7:])
	return nil
}

func (b *RCQueryResultResponse) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, b.QueryID)
	length += n
	n, _ = buf.WriteString(b.Content)
	length += n
	if length != (7 + len(b.Content)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}
