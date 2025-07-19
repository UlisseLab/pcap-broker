// SPDX-FileCopyrightText: 2023 - 2025 VaiTon <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Yun Zheng Hu <hu@fox-it.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	broker "github.com/UlisseLab/pcap-broker"
)

var (
	listenAddr = flag.String("listen", "", "listen address for pcap-over-ip (eg: localhost:4242)")
	debug      = flag.Bool("debug", false, "enable debug logging")
	json       = flag.Bool("json", false, "enable json logging")
)

var (
	clients   []chan<- gopacket.Packet
	clientsMx = &sync.RWMutex{}
)

func main() {
	flag.Parse()

	if !*json {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	}

	globalCtx, cancelGlobalCtx := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-globalCtx.Done()
		cancelGlobalCtx()
	}()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if *listenAddr == "" {
		*listenAddr = os.Getenv("LISTEN_ADDRESS")
		if *listenAddr == "" {
			*listenAddr = "localhost:4242"
		}
	}

	log.Debug().Str("listenAddr", *listenAddr).Send()

	// Read from process stdout pipe
	var pcapStream *os.File

	log.Info().Msg("reading pcap data from stdin. EOF to stop")
	pcapStream = os.Stdin

	log.Debug().Msg("opening pcap file")
	pcapHandle, err := pcap.OpenOfflineFile(pcapStream)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open pcap file")
	}
	log.Debug().Msg("opened pcap file")

	log.Debug().Msg("starting broker...")
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	broker := broker.NewBroker(pcapHandle.LinkType())
	broker.Input = packetSource.Packets()
	go func() {
		// stop the global context when the broker stops
		broker.Start(globalCtx)
		log.Debug().Msg("broker stopped")
		cancelGlobalCtx()
	}()
	log.Debug().Msg("broker started")

	log.Debug().Msg("starting server...")
	go func() {
		// stop the global context when the server stops
		listen(globalCtx, broker)
		log.Debug().Msg("server stopped")
		cancelGlobalCtx()
	}()

	<-globalCtx.Done()
	log.Debug().Msg("context done, shutting down...")

	pcapHandle.Close()
	log.Debug().Msg("pcap handle closed")
}

func listen(ctx context.Context, b *broker.Broker) {
	// Start server
	config := net.ListenConfig{}
	l, err := config.Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	go func() {
		<-ctx.Done()
		log.Debug().Msg("closing listener")
		err := l.Close()
		if err != nil {
			log.Err(err).Msg("failed to close listener")
		}
	}()

	log.Info().Msgf("listening on %s, press Ctrl+C to stop", *listenAddr)

	// accept connections
	for {
		conn, err := l.Accept()
		if err != nil && errors.Is(ctx.Err(), context.Canceled) {
			break
		} else if err != nil {
			log.Err(err).Msg("failed to accept connection")
			continue
		}

		client := broker.NewClient(conn.RemoteAddr().String(), conn)
		log.Info().Str("clientID", client.Id()).Msg("new client connected")

		// Add client to broker
		b.AddClient(client)
	}
}
