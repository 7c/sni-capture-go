package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/7c/mygobase"
	"github.com/7c/sni-capture-go/pkg/api"
	"github.com/7c/sni-capture-go/pkg/capture"
	"github.com/7c/sni-capture-go/pkg/config"
	"github.com/7c/sni-capture-go/pkg/logger"
	"github.com/7c/sni-capture-go/pkg/network"
	"github.com/alecthomas/kingpin/v2"
)

var (
	app = kingpin.New("sni-capture", "A tool to capture SNI information from TLS handshakes")

	direction = app.Flag("direction", "Direction of TLS handshake to capture (in|out|both)").
			Short('d').
			Default("both").
			Enum("in", "out", "both")

	ports = app.Flag("port", "Ports to listen for TLS handshake").
		Short('p').
		Default("443").
		Ints()

	output = app.Flag("output", "Log output file").
		Short('o').
		String()

	iface = app.Flag("iface", "Network interface to attach to").
		Short('i').
		String()

	listIfaces = app.Flag("listiface", "List all available interfaces").
			Bool()

	verbose = app.Flag("verbose", "Enable verbose output").
		Short('v').
		Bool()

	ja3 = app.Flag("ja3", "Show JA3 fingerprint for each TLS handshake").
		Bool()

	json = app.Flag("json", "Output in JSON format").
		Bool()

	once = app.Flag("once", "Show each SNI only once per session").
		Short('1').
		Bool()

	apiServer = app.Flag("apiserver", "Enable API server").
			Bool()

	apiServerHost = app.Flag("apiserver-host", "API server host").
			Default("127.0.0.1").
			String()

	apiServerPort = app.Flag("apiserver-port", "API server port").
			Default("7810").
			Int()

	apiServerLog = app.Flag("apiserver-log", "API server log file").
			String()

	lockPort = app.Flag("lockport", "Port to use for locking mechanism").
			Short('l').
			Default("23554").
			Int()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Initialize logger with verbose mode and once mode
	logger.InitLogger(*output, *verbose, *once, *ja3, *json, *direction)

	// If listifaces flag is set, show interfaces and exit
	if *listIfaces {
		network.ListInterfaces()
		return
	}

	// Get network interface
	selectedIface, err := network.GetInterface(*iface)
	if err != nil {
		logger.Fatal("Failed to get network interface: %v", err)
	}

	// Create configuration
	cfg := config.NewConfig(*direction, *ports, selectedIface, *verbose, lockPort)

	if mygobase.LockPort(*lockPort) == nil {
		logger.Fatal("Failed to lock port %d", *lockPort)
	}

	// Initialize API server if enabled
	var server *api.Server
	if *apiServer {
		server = api.NewServer(*apiServerHost, *apiServerPort, *apiServerLog)
		go func() {
			logger.LogSystem.Printf("Starting API server on %s:%d", *apiServerHost, *apiServerPort)
			if err := server.Start(); err != nil {
				logger.LogSystem.Printf("API server error: %v", err)
			}
		}()
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start packet capture in a goroutine
	done := make(chan struct{})
	go func() {
		capture.StartCapture(cfg, server)
		close(done)
	}()

	// Wait for signal or completion
	select {
	case <-sigChan:
		logger.LogSystem.Println("Received shutdown signal, cleaning up...")
	case <-done:
		logger.LogSystem.Println("Capture completed, cleaning up...")
	}

	// Clean up resources
	logger.StopCleanup()
}
