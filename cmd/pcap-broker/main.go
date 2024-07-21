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

	"pcap-broker/pkg/pcapclient"
)

var (
	listenAddr = flag.String("listen", "", "listen address for pcap-over-ip (eg: localhost:4242)")
	debug      = flag.Bool("debug", false, "enable debug logging")
	json       = flag.Bool("json", false, "enable json logging")
	logspeed   = flag.Bool("logspeed", false, "log packet speed")
)

var (
	clients   []*pcapclient.Client
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

	ctx, cancelFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-ctx.Done()
		cancelFunc()
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

	log.Debug().Str("stream", pcapStream.Name()).Msg("opening pcap file")
	pcapHandle, err := pcap.OpenOfflineFile(pcapStream)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open pcap file")
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	log.Debug().Msg("starting packet processing")
	go processPackets(ctx, packetSource)

	log.Debug().Str("addr", *listenAddr).Msg("starting server")
	listen(ctx, pcapHandle)

	log.Warn().Msg("PCAP-over-IP server exiting")
}

func listen(ctx context.Context, handle *pcap.Handle) {
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

	log.Info().Str("listenAddr", *listenAddr).Msg("started PCAP-over-IP server, CTRL+C to stop")

	// accept connections
	for {
		conn, err := l.Accept()
		if err != nil && errors.Is(ctx.Err(), context.Canceled) {
			break
		} else if err != nil {
			log.Err(err).Msg("failed to accept connection")
			continue
		}

		acceptClient(conn, handle)
	}
}

func acceptClient(conn net.Conn, handle *pcap.Handle) {

	logger := log.With().Stringer("remoteAddr", conn.RemoteAddr()).Logger()

	logger.Info().Int("connected", len(clients)+1).Msg("accepted connection")
	// Create a new pcap writer
	client := pcapclient.NewPcapClient(conn)

	// Write pcap header
	err := client.WritePcapHeader(handle.LinkType())
	if err != nil {
		logger.Warn().Err(err).Msg("failed to write pcap header")
		_ = conn.Close() // try to close connection
		return
	}

	// send packets to client
	clientsMx.Lock()
	clients = append(clients, client)
	clientsMx.Unlock()
}

func processPackets(ctx context.Context, source *gopacket.PacketSource) {

	relayedPackets := 0
	startTime := time.Now()

	for packet := range source.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		relayedPackets++

		clientsMx.RLock()
		for _, client := range clients {

			err := client.SendPacket(packet)
			if err != nil {
				log.Debug().Err(err).Msg("failed to send packet")
				err = client.Close()
				if err != nil {
					log.Warn().Err(err).Msg("failed to close connection")
				}
			}

		}
		clientsMx.RUnlock()

		// remove closed clients
		// TODO: not the best way to do this, but it works for now
		clientsMx.Lock()
		for i := 0; i < len(clients); i++ {
			if clients[i].Closed() {
				log.Info().Stringer("remote", clients[i].RemoteAddr()).
					Int("connected", len(clients)-1).Msg("closed connection")
				clients = append(clients[:i], clients[i+1:]...)
				i--
			}
		}
		clientsMx.Unlock()

		// log every 30 seconds
		if time.Since(startTime) > 30*time.Second {
			if *logspeed {
				log.Info().Int("packets", relayedPackets).
					Float64("pps", float64(relayedPackets)/time.Since(startTime).Seconds()).
					Msg("packet speed")
				startTime = time.Now()
			}

			relayedPackets = 0 // to avoid overflow
		}
	}
}
