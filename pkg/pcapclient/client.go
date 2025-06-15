package pcapclient

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Client struct {
	ID      string
	Packets chan gopacket.Packet
	Closed  chan struct{}

	conn   net.Conn
	writer *pcapgo.Writer
}

func NewPcapClient(conn net.Conn) *Client {
	return &Client{
		ID:      conn.RemoteAddr().String(),
		Packets: make(chan gopacket.Packet, 100),
		Closed:  make(chan struct{}),
		writer:  pcapgo.NewWriter(conn),
		conn:    conn,
	}
}

func (c *Client) WritePcapHeader(linkType layers.LinkType) error {
	err := c.writer.WriteFileHeader(65535, linkType)
	if err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}
	return nil
}

func (c *Client) SendPacket(p gopacket.Packet) error {
	c.conn.SetWriteDeadline(time.Now().Add(clientTimeout))

	info := p.Metadata().CaptureInfo

	err := c.writer.WritePacket(info, p.Data())
	if err != nil {
		_ = c.conn.Close() // chiusura esplicita
		return fmt.Errorf("can't write packet: %w", err)
	}
	return nil
}
