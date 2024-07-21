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

	log.Debug().Msg("opening pcap file")
	handle, err := pcap.OpenOfflineFile(pcapStream)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open pcap file")
	}
	log.Debug().Msg("opened pcap file")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	log.Debug().Msg("starting packet processing")
	go processPackets(ctx, packetSource)

	log.Debug().Msg("starting server")
	listen(err, ctx, cancelFunc, handle)

	log.Warn().Msg("PCAP-over-IP server exiting")
}

func listen(err error, ctx context.Context, cancelFunc context.CancelFunc, handle *pcap.Handle) {
	// Start server
	config := net.ListenConfig{}
	l, err := config.Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	go func() {
		<-ctx.Done()
		log.Debug().Msg("closing listener")
		cancelFunc()
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

	logger := log.With().Stringer("remote", conn.RemoteAddr()).Logger()

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
	logger.Debug().Msg("starting packet sender")
	pktChan := make(chan gopacket.Packet, 100)

	clientsMx.Lock()
	clients = append(clients, pktChan)
	clientsMx.Unlock()

	errChan := client.SendPackets(pktChan)

	// wait for error or close
	go func() {
		err := <-errChan
		if err != nil {
			logger.Debug().Err(err).Msg("client error")
			logger.Info().Int("connected", len(clients)-1).Msg("closing connection")
		}

		clientsMx.Lock()
		for i, c := range clients {
			if c == pktChan {
				clients = append(clients[:i], clients[i+1:]...)
				break
			}
		}
		clientsMx.Unlock()

		close(pktChan)
	}()
}

func processPackets(ctx context.Context, source *gopacket.PacketSource) {
	for packet := range source.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		clientsMx.RLock()
		for _, client := range clients {

			// do not wait if channel is full
			select {
			case client <- packet:
			default:
			}

		}
		clientsMx.RUnlock()

	}
}
