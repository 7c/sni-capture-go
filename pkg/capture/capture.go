package capture

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/7c/sni-capture-go/pkg/api"
	"github.com/7c/sni-capture-go/pkg/config"
	"github.com/7c/sni-capture-go/pkg/logger"
	"github.com/7c/sni-capture-go/pkg/shared"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SNIInfo holds information about a captured SNI
type SNIInfo struct {
	SrcIP     string
	DstIP     string
	DstPort   int
	SNI       string
	Verified  bool
	SeenCount int
}

var (
	sniMap   = make(map[string]*SNIInfo)
	mutex    sync.Mutex
	lockPort *int
)

func PreparePCAP(cfg *config.Config, apiServer *api.Server) *pcap.Handle {
	// 800 bytes is enough for JA3 fingerprinting
	handle, err := pcap.OpenLive(cfg.Interface.Name, 800, true, pcap.BlockForever)
	if err != nil {
		logger.Fatal("Error opening pcap device: %v", err)
	}

	// Build BPF filter
	filter := fmt.Sprintf("tcp and (dst port %d", cfg.Ports[0])
	for i := 1; i < len(cfg.Ports); i++ {
		filter += fmt.Sprintf(" or dst port %d", cfg.Ports[i])
	}
	filter += ")"

	// Display API server settings if enabled
	if apiServer != nil {
		color.Cyan("🌐 API Server: http://%s:%d", apiServer.GetHost(), apiServer.GetPort())
		if logFile := apiServer.GetLogFile(); logFile != "" {
			color.Cyan("📝 API Log: http://%s:%d%s", apiServer.GetHost(), apiServer.GetPort(), logFile)
		}
	}

	if cfg.Verbose {
		logger.Debugf("BPF Filter: %s", color.GreenString(filter))
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		logger.Fatal("Error setting BPF filter: %v", err)
	}

	return handle
}

func HandlePacket(packet gopacket.Packet, apiServer *api.Server, cfg *config.Config) {
	if packet.ErrorLayer() != nil {
		logger.Printf("Error decoding packet: %v", packet.ErrorLayer().Error())
		return
	}

	// Get IP layer
	var ipLayer gopacket.Layer
	if ipLayer = packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
		if ipLayer = packet.Layer(layers.LayerTypeIPv6); ipLayer == nil {
			logger.Printf("No IP layer found")
			return
		}
	}

	// Parse TCP metadata
	meta := shared.ParseTCPMetadata(&packet, nil, nil, ipLayer, false)
	if meta == nil {
		return
	}

	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		logger.Printf("No TCP layer found")
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// Process TLS handshake
	if len(tcp.Payload) > 0 && tcp.Payload[0] == 0x16 {
		clientHello := tlsx.ClientHelloBasic{}
		if err := clientHello.Unmarshal(tcp.Payload); err != nil {
			if logger.IsVerbose() {
				logger.Printf("Error parsing ClientHello: %v", err)
			}
			return
		}

		// Get JA3 fingerprint
		ja3Fingerprint := ja3.DigestHexPacket(packet)
		if ja3Fingerprint == "" {
			return
		}

		// Update metadata with trimmed and lowercase SNI
		meta.SNI = strings.TrimSpace(strings.ToLower(clientHello.SNI))
		meta.JA3Fingerprint = ja3Fingerprint
		meta.T = time.Now()

		// Store in sessions
		shared.Mutex1.Lock()
		if _, ok := shared.Sessions[meta.Identifier]; !ok {
			shared.Sessions[meta.Identifier] = meta
		} else {
			temp := shared.Sessions[meta.Identifier]
			temp.Count++
			shared.Sessions[meta.Identifier] = temp
		}
		shared.Mutex1.Unlock()

		// Determine direction using public IP from config
		direction := "out"
		if cfg.PublicIP != "" && meta.SourceIP != cfg.PublicIP {
			direction = "in"
		}

		// Add to API server if enabled
		if apiServer != nil {
			apiServer.AddSNI(api.SNIData{
				Timestamp: meta.T.Format(time.RFC3339),
				SourceIP:  meta.SourceIP,
				DestIP:    meta.DestIP,
				DestPort:  meta.DestPort,
				SNI:       meta.SNI,
				Verified:  true,
				SeenCount: meta.Count,
				JA3:       meta.JA3Fingerprint,
				Direction: direction,
			})
		}

		// Log SNI information
		logger.PrintSNI(
			meta.SourceIP,
			meta.DestIP,
			meta.DestPort,
			meta.SNI,
			true, // SSL verified
			meta.Count,
			&packet,
		)
	}
}

func StartCapture(cfg *config.Config, apiServer *api.Server) {
	// Initialize lock port
	lockPort = cfg.LockPort

	// Display configuration
	displayConfig(cfg, "")

	// Prepare packet capture
	handle := PreparePCAP(cfg, apiServer)
	defer handle.Close()

	// Start cleanup worker
	go Worker_cleanup(logger.LogSystem, 10*time.Minute)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process TLS handshake
		HandlePacket(packet, apiServer, cfg)
	}
}

func Worker_cleanup(log *log.Logger, retention time.Duration) {
	logger.LogSystem.Println("Starting cleanup worker...")
	for {
		deleted := 0
		shared.Mutex1.Lock()

		// Clean up MatchStorage
		for k, v := range shared.MatchStorage {
			if time.Since(v.T) > retention {
				delete(shared.MatchStorage, k)
				deleted++
			}
		}

		// Clean up Sessions
		for k, v := range shared.Sessions {
			if time.Since(v.T) > retention {
				delete(shared.Sessions, k)
				deleted++
			}
		}

		shared.Mutex1.Unlock()

		if deleted > 0 {
			logger.LogSystem.Printf("Deleted %d entries from cache", deleted)
		}

		time.Sleep(1 * time.Minute)
	}
}

// displayConfig shows the current configuration
func displayConfig(cfg *config.Config, filter string) {
	// Display configuration with emojis and colors
	color.Cyan("🔒 Lock Port: %d", *lockPort)
	color.Cyan("🔍 Monitoring ports: %v", cfg.Ports)
	color.Cyan("📡 Interface: %s", cfg.Interface.Name)
	if logger.GetOutputFile() != "" {
		color.Cyan("📝 Log file: %s", logger.GetOutputFile())
	}
	color.Cyan("📊 Direction: %s", cfg.Direction)

	if cfg.Verbose {
		logger.Debugf("BPF Filter: %s", filter)
		logger.Debugf("Capture direction: %s", cfg.Direction)
		logger.Debugf("Monitoring ports: %v", cfg.Ports)
	}
}

// createBPFFilter creates a BPF filter string based on configuration
func createBPFFilter(cfg *config.Config) string {
	filter := "tcp and ("

	// Add ports to filter
	for i, port := range cfg.Ports {
		if i > 0 {
			filter += " or "
		}
		filter += fmt.Sprintf("port %d", port)
	}

	filter += ")"
	logger.Printf("BPF Filter: %s", filter)
	return filter
}

// processPacket processes a captured packet
func processPacket(packet gopacket.Packet, cfg *config.Config) {
	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		if cfg.Verbose {
			logger.Debugf("Packet is not TCP, skipping")
		}
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// Check if this is a TLS handshake
	if len(tcp.Payload) < 5 || tcp.Payload[0] != 0x16 {
		if cfg.Verbose {
			logger.Debugf("Packet is not TLS handshake, skipping")
		}
		return
	}

	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		if cfg.Verbose {
			logger.Debugf("Packet is not IPv4, skipping")
		}
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)

	if cfg.Verbose {
		logger.Debugf("Processing TLS handshake: %s:%d -> %s:%d",
			ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	}

	// Extract SNI from TLS handshake
	sni := extractSNI(tcp.Payload)
	if sni == "" {
		if cfg.Verbose {
			logger.Debugf("No SNI found in TLS handshake")
		}
		return
	}

	if cfg.Verbose {
		logger.Debugf("Found SNI: %s", sni)
	}

	// Update SNI information
	key := fmt.Sprintf("%s:%s:%d:%s", ip.SrcIP, ip.DstIP, tcp.DstPort, sni)

	mutex.Lock()
	defer mutex.Unlock()

	info, exists := sniMap[key]
	if !exists {
		info = &SNIInfo{
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			DstPort:   int(tcp.DstPort),
			SNI:       sni,
			Verified:  true, // Default to true, will be updated if verification fails
			SeenCount: 1,
		}
		sniMap[key] = info
		if cfg.Verbose {
			logger.Debugf("New SNI entry created: %s", key)
		}
	} else {
		info.SeenCount++
		if cfg.Verbose {
			logger.Debugf("Updated SNI entry: %s (seen %d times)", key, info.SeenCount)
		}
	}

	// Log the SNI information
	// logger.PrintSNI(info.SrcIP, info.DstIP, info.DstPort, info.SNI, info.Verified, info.SeenCount)
}

// extractSNI extracts the Server Name Indication from TLS handshake
func extractSNI(payload []byte) string {
	// Skip TLS record header
	if len(payload) < 5 {
		return ""
	}
	payload = payload[5:]

	// Skip handshake header
	if len(payload) < 4 {
		return ""
	}
	payload = payload[4:]

	// Skip random bytes and session ID
	if len(payload) < 32 {
		return ""
	}
	payload = payload[32:]

	// Skip session ID length and session ID
	if len(payload) < 1 {
		return ""
	}
	sessionIDLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sessionIDLen {
		return ""
	}
	payload = payload[sessionIDLen:]

	// Skip cipher suites
	if len(payload) < 2 {
		return ""
	}
	cipherSuitesLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < cipherSuitesLen {
		return ""
	}
	payload = payload[cipherSuitesLen:]

	// Skip compression methods
	if len(payload) < 1 {
		return ""
	}
	compressionMethodsLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < compressionMethodsLen {
		return ""
	}
	payload = payload[compressionMethodsLen:]

	// Skip extensions length
	if len(payload) < 2 {
		return ""
	}
	extensionsLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < extensionsLen {
		return ""
	}

	// Parse extensions
	for len(payload) >= 4 {
		extType := int(payload[0])<<8 | int(payload[1])
		extLen := int(payload[2])<<8 | int(payload[3])
		payload = payload[4:]

		if extType == 0 { // SNI extension
			if len(payload) < extLen {
				return ""
			}
			extData := payload[:extLen]
			payload = payload[extLen:]

			// Parse SNI data
			if len(extData) < 2 {
				return ""
			}
			sniListLen := int(extData[0])<<8 | int(extData[1])
			extData = extData[2:]
			if len(extData) < sniListLen {
				return ""
			}

			// Get first SNI entry
			if len(extData) < 3 {
				return ""
			}
			sniType := extData[0]
			sniLen := int(extData[1])<<8 | int(extData[2])
			extData = extData[3:]
			if sniType != 0 || len(extData) < sniLen {
				return ""
			}

			return string(extData[:sniLen])
		}

		if len(payload) < extLen {
			return ""
		}
		payload = payload[extLen:]
	}

	return ""
}
