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
	conn   net.Conn
	writer *pcapgo.Writer
	closed bool
}

func NewPcapClient(conn net.Conn) (*Client, error) {
	c := &Client{
		writer: pcapgo.NewWriter(conn),
		conn:   conn,
	}
	// set a timeout for the connection
	err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("set write deadline: %w", err)
	}
	return c, nil
}

func (c *Client) WritePcapHeader(linkType layers.LinkType) (err error) {
	if c.closed {
		return
	}

	err = c.writer.WriteFileHeader(65535, linkType)
	if err != nil {
		err = fmt.Errorf("write pcap header: %w", err)
	}
	return
}

func (c *Client) SendPacket(p gopacket.Packet) error {
	if c.closed {
		return nil
	}

	info := p.Metadata().CaptureInfo
	err := c.writer.WritePacket(info, p.Data())
	if err != nil {
		return fmt.Errorf("write packet: %w", err)
	}
	return nil
}

func (c *Client) Close() error {
	c.closed = true
	return c.conn.Close()
}

func (c *Client) Closed() bool         { return c.closed }
func (c *Client) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
