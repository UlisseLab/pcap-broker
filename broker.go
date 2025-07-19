// SPDX-FileCopyrightText: 2023 - 2025 VaiTon <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Yun Zheng Hu <hu@fox-it.com>
//
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var clientTimeout = 1 * time.Second // timeout for sending packets to clients

type Broker struct {
	Input chan gopacket.Packet // incoming packets to be sent to clients

	clients   map[string]*Client // map of clients by ID
	clientAdd chan *Client       // to add a new client
	clientRem chan string        // to remove a client by ID

	linkType layers.LinkType // link type for pcap header
}

func NewBroker(linkType layers.LinkType) *Broker {
	return &Broker{
		clientAdd: make(chan *Client, 1),           // size 1 to allow len()
		clientRem: make(chan string, 1),            // size 1 to allow len()
		Input:     make(chan gopacket.Packet, 100), // buffered channel for incoming packets
		clients:   make(map[string]*Client),
		linkType:  linkType,
	}
}

func (b *Broker) AddClient(client *Client) {
	b.clientAdd <- client
}

func (b *Broker) Start(ctx context.Context) error {
	brokerLog := log.With().Str("component", "pcap-broker").Logger()

	for {
		select {
		case client := <-b.clientAdd:
			brokerLog.Debug().Msgf("adding client %s", client.id)
			b.registerClient(client)

			brokerLog.Debug().Msgf("starting goroutine for client %s", client.id)
			go b.handleClient(client)

			brokerLog.Info().Msgf("client %s added, total clients: %d", client.id, len(b.clients))

		case id := <-b.clientRem:
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

func (b *Broker) registerClient(c *Client) {
	b.clients[c.id] = c
}

func (b *Broker) unregisterClient(id string) {
	if client, ok := b.clients[id]; ok {
		close(client.packets)
		delete(b.clients, id)
	}
}

func (b *Broker) broadcastPacket(packet gopacket.Packet) {
	for _, client := range b.clients {
		select {
		case <-time.After(clientTimeout):
			log.Warn().Msgf("timeout sending to client %s, removing", client.id)
			b.unregisterClient(client.id)

		case client.packets <- packet:
		}
	}
}

func (b *Broker) closeAllClients() {
	log.Debug().Msgf("closing all clients, total: %d", len(b.clients))
	for id, client := range b.clients {
		close(client.packets)
		delete(b.clients, id)
		log.Debug().Msgf("closed client %s", id)
	}
}

func (b *Broker) handleClient(c *Client) {
	err := c.WritePcapHeader(b.linkType)
	if err != nil {
		log.Warn().Msgf("failed to write pcap header to client %s: %v", c.id, err)
		b.clientRem <- c.id
		return
	}

	for data := range c.packets {
		err := c.SendPacket(data)
		if err != nil {
			log.Warn().Msgf("failed to send packet to client %s: %v", c.id, err)
			log.Debug().Msgf("asking the broker to remove client %s", c.id)
			b.clientRem <- c.id
			return
		}
	}
}
