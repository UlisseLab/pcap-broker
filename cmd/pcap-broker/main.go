package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type PcapClient struct {
	writer       *pcapgo.Writer
	totalPackets uint64
	totalBytes   uint64
}

func lookupHostnameWithTimeout(addr net.Addr, timeout time.Duration) (string, string, error) {
	// Extract the IP address and port from the Addr object
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return "", "", fmt.Errorf("unsupported address type: %T", addr)
	}
	ip := tcpAddr.IP.String()
	port := fmt.Sprintf("%d", tcpAddr.Port)

	// Create a new context with the given timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a new Resolver and perform the IP lookup with the given context
	resolver := net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return "", "", err
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("no hostnames found for %s", ip)
	}

	// Return the first IP address found and the original port
	return names[0], port, nil
}

var (
	listenAddress   = flag.String("listen", "", "listen address for pcap-over-ip (eg: localhost:4242)")
	noReverseLookup = flag.Bool("n", false, "disable reverse lookup of connecting PCAP-over-IP client IP address")
	debug           = flag.Bool("debug", false, "enable debug logging")
	json            = flag.Bool("json", false, "enable json logging")
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

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if *listenAddress == "" {
		*listenAddress = os.Getenv("LISTEN_ADDRESS")
		if *listenAddress == "" {
			*listenAddress = "localhost:4242"
		}
	}

	log.Debug().Str("listenAddress", *listenAddress).Send()

	// Read from process stdout pipe
	var pcapStream *os.File

	log.Info().Msg("reading pcap data from stdin. EOF to stop")
	pcapStream = os.Stdin

	handle, err := pcap.OpenOfflineFile(pcapStream)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open pcap file")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	// Create connections to PcapClient map
	connMap := map[net.Conn]PcapClient{}

	go processPackets(ctx, packetSource, connMap)

	log.Info().Msgf("PCAP-over-IP server listening on %v. press CTRL-C to exit", *listenAddress)

	config := net.ListenConfig{}
	l, err := config.Listen(ctx, "tcp", *listenAddress)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	// close listener on context cancel
	go func() {
		<-ctx.Done()
		log.Debug().Msg("closing listener")
		cancelFunc()
		err := l.Close()
		if err != nil {
			log.Err(err).Msg("failed to close listener")
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil && ctx.Err() == nil {
			log.Fatal().Err(err).Msg("failed to accept connection")
		} else if errors.Is(ctx.Err(), context.Canceled) {
			break
		}

		if *noReverseLookup {
			log.Printf("PCAP-over-IP connection from %v", conn.RemoteAddr())
		} else {
			ip, port, err := lookupHostnameWithTimeout(conn.RemoteAddr(), 100*time.Millisecond)
			if err != nil {
				log.Printf("PCAP-over-IP connection from %v", conn.RemoteAddr())
			} else {
				log.Printf("PCAP-over-IP connection from %s:%s", ip, port)
			}
		}

		writer := pcapgo.NewWriter(conn)

		// Write pcap header
		err = writer.WriteFileHeader(65535, handle.LinkType())
		if err != nil {
			log.Err(err).Msg("failed to write pcap header")
			err := conn.Close()
			if err != nil {
				log.Err(err).Msg("failed to close connection")
			}

			continue
		}

		// add connection to map
		connMap[conn] = PcapClient{writer: writer}
	}

	log.Info().Msg("PCAP-over-IP server exiting")
}

func processPackets(
	ctx context.Context,
	packetSource *gopacket.PacketSource,
	connMap map[net.Conn]PcapClient,
) {
	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for conn, stats := range connMap {
			ci := packet.Metadata().CaptureInfo
			err := stats.writer.WritePacket(ci, packet.Data())
			if err != nil {
				log.Err(err).Msg("failed to write packet to connection")
				delete(connMap, conn)
				err := conn.Close()
				if err != nil {
					log.Err(err).Msg("failed to close connection")
				}
				continue
			}
			stats.totalPackets += 1
			stats.totalBytes += uint64(ci.CaptureLength)
		}
	}
}
