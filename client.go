// SPDX-FileCopyrightText: 2023 - 2025 VaiTon <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Yun Zheng Hu <hu@fox-it.com>
//
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Client struct {
	id      string               // unique identifier for the client
	packets chan gopacket.Packet // channel to send packets to the client
	closed  chan struct{}        // channel to signal when the client is closed

	writer *pcapgo.Writer
}

func NewClient(id string, w io.Writer) *Client {
	return &Client{
		id:      id,
		packets: make(chan gopacket.Packet, 100),
		closed:  make(chan struct{}),
		writer:  pcapgo.NewWriter(w),
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
	info := p.Metadata().CaptureInfo
	err := c.writer.WritePacket(info, p.Data())
	if err != nil {
		return fmt.Errorf("can't write packet: %w", err)
	}
	return nil
}

func (c *Client) Id() string { return c.id }
