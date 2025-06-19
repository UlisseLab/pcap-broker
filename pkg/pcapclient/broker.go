// SPDX-FileCopyrightText: 2023 - 2025 VaiTon <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Yun Zheng Hu <hu@fox-it.com>
//
// SPDX-License-Identifier: Apache-2.0

package pcapclient

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var clientTimeout = 1 * time.Second // timeout for sending packets to clients

type PcapBroker struct {
	Add    chan *Client // to add a new client
	Remove chan string  // to remove a client by ID

	Input chan gopacket.Packet // incoming packets to be sent to clients

	clients  map[string]*Client
	linkType layers.LinkType // link type for pcap header
}

func NewPcapBroker(linkType layers.LinkType) *PcapBroker {
	return &PcapBroker{
		Add:      make(chan *Client, 1),           // size 1 to allow len()
		Remove:   make(chan string, 1),            // size 1 to allow len()
		Input:    make(chan gopacket.Packet, 100), // buffered channel for incoming packets
		clients:  make(map[string]*Client),
		linkType: linkType,
	}
}

func (b *PcapBroker) Start(ctx context.Context) error {
	brokerLog := log.With().Str("component", "pcap-broker").Logger()

	for {
		select {
		case client := <-b.Add:
			brokerLog.Debug().Msgf("adding client %s", client.ID)
			b.registerClient(client)

			brokerLog.Debug().Msgf("starting goroutine for client %s", client.ID)
			go b.handleClient(client)

			brokerLog.Info().Msgf("client %s added, total clients: %d", client.ID, len(b.clients))

		case id := <-b.Remove:
			brokerLog.Debug().Msgf("removing client %s", id)
			b.unregisterClient(id)

			brokerLog.Info().Msgf("client %s removed, total clients: %d", id, len(b.clients))

		case packet, ok := <-b.Input:
			if !ok {
				brokerLog.Warn().Msg("input channel closed, stopping broker")
				return nil
			}
			b.broadcastPacket(packet)

		case <-ctx.Done():
			brokerLog.Info().Msg("broker shutting down")
			b.closeAllClients()
			return nil
		}
	}
}

func (b *PcapBroker) registerClient(c *Client) {
	b.clients[c.ID] = c
}

func (b *PcapBroker) unregisterClient(id string) {
	if client, ok := b.clients[id]; ok {
		close(client.Packets)
		delete(b.clients, id)
	}
}

func (b *PcapBroker) broadcastPacket(packet gopacket.Packet) {
	for _, client := range b.clients {
		select {
		case <-time.After(clientTimeout):
			log.Warn().Msgf("timeout sending to client %s, removing", client.ID)
			b.unregisterClient(client.ID)

		case client.Packets <- packet:
		}
	}
}

func (b *PcapBroker) closeAllClients() {
	log.Debug().Msgf("closing all clients, total: %d", len(b.clients))
	for id, client := range b.clients {
		close(client.Packets)
		if err := client.conn.Close(); err != nil {
			log.Warn().Msgf("failed to close connection for client %s: %v", id, err)
		}
		delete(b.clients, id)
		log.Debug().Msgf("closed client %s", id)
	}
}

func (b *PcapBroker) handleClient(c *Client) {
	err := c.WritePcapHeader(b.linkType)
	if err != nil {
		log.Warn().Msgf("failed to write pcap header to client %s: %v", c.ID, err)
		b.Remove <- c.ID
		return
	}

	for data := range c.Packets {
		err := c.SendPacket(data)
		if err != nil {
			log.Warn().Msgf("failed to send packet to client %s: %v", c.ID, err)
			log.Debug().Msgf("asking the broker to remove client %s", c.ID)
			b.Remove <- c.ID
			return
		}
	}
}
