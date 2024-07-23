package pcapclient

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
)

type Client struct {
	conn         net.Conn
	writer       *pcapgo.Writer
	totalPackets uint64
	totalBytes   uint64
}

func NewPcapClient(conn net.Conn) *Client {
	return &Client{
		writer: pcapgo.NewWriter(conn),
		conn:   conn,
	}
}
func (c *Client) WritePcapHeader(linkType layers.LinkType) (err error) {
	err = c.writer.WriteFileHeader(65535, linkType)
	if err != nil {
		err = fmt.Errorf("write pcap header: %w", err)
	}
	return
}

func (c *Client) SendPackets(packets <-chan gopacket.Packet) <-chan error {
	errChan := make(chan error)

	go func() {

		for pkt := range packets {
			err := c.SendPacket(pkt)
			if err != nil {
				errChan <- err
			}
		}

		// when the packet channel is closed, close the error channel
		log.Debug().Str("remoteAddr", c.conn.RemoteAddr().String()).Msg("client loop exited. closing connection")
		_ = c.Close()
		close(errChan)
	}()

	return errChan
}

func (c *Client) SendPacket(p gopacket.Packet) error {
	info := p.Metadata().CaptureInfo
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := c.writer.WritePacket(info, p.Data())
	if err != nil {
		return fmt.Errorf("write packet: %w", err)
	}
	c.totalPackets += 1
	c.totalBytes += uint64(info.CaptureLength)
	return nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}
