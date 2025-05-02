package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/dreadl0ck/ja3"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/google/gopacket"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// LogCommon is the logger for common messages
	LogCommon *log.Logger
	// LogDebug is the logger for debug messages
	LogDebug *log.Logger
	// LogSystem is the logger for system messages (always to console)
	LogSystem *log.Logger
	// VerboseMode indicates if debug logging is enabled
	VerboseMode bool
	// OnceMode indicates if we should show each SNI only once
	OnceMode bool
	// Ja3Mode indicates if we should show JA3 fingerprints
	Ja3Mode bool
	// JsonMode indicates if we should output in JSON format
	JsonMode bool
	// outputFile stores the current log file path
	outputFile string
	// seenSNIs tracks SNIs we've already seen in once mode
	seenSNIs = make(map[string]int)
	// seenMutex protects seenSNIs map
	seenMutex sync.RWMutex
	// cleanupTicker for periodic cleanup of seenSNIs
	cleanupTicker *time.Ticker
	// cleanupDone channel to stop cleanup goroutine
	cleanupDone chan struct{}
	// externalIP stores the detected external IP
	externalIP string
	// configuredDirection stores the user-specified direction
	configuredDirection string
)

// PublicIP tries to determine the external IP address
func PublicIP() (string, error) {
	if externalIP != "" {
		return externalIP, nil
	}

	client := resty.New().SetTimeout(5 * time.Second) // Short timeout
	for _, host := range []string{
		"https://ip4.ip8.com",
		"https://ip8.com/ip",
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://myexternalip.com/raw",
	} {
		resp, err := client.R().Get(host)
		if err != nil {
			LogSystem.Printf("PublicIP() @%s Error: %s", host, err.Error())
			continue
		}

		if resp.StatusCode() == 200 {
			ip := string(resp.Body())
			// Basic IP validation
			if len(ip) > 0 && ip[0] >= '0' && ip[0] <= '9' {
				LogSystem.Printf("Determined external IP: %s", ip)
				externalIP = ip
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("could not determine public IP address")
}

// SNIEvent represents a single SNI capture event in JSON format
type SNIEvent struct {
	Timestamp string `json:"timestamp"`
	SourceIP  string `json:"source_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	SNI       string `json:"sni"`
	Verified  bool   `json:"verified"`
	SeenCount int    `json:"seen_count"`
	JA3       string `json:"ja3,omitempty"`
	Direction string `json:"dir"`
}

// InitLogger initializes the logger with both file and console output
func InitLogger(logFile string, verbose bool, once bool, ja3 bool, json bool, direction string) {
	VerboseMode = verbose
	OnceMode = once
	Ja3Mode = ja3
	JsonMode = json
	outputFile = logFile
	configuredDirection = direction

	var writer interface {
		Write([]byte) (int, error)
	}

	// Initialize system logger (always to console)
	LogSystem = log.New(os.Stderr, "", log.LstdFlags)

	// Try to detect external IP
	if ip, err := PublicIP(); err == nil {
		color.Yellow("🌐 External IP: %s", ip)
	} else {
		LogSystem.Printf("Warning: %v", err)
	}

	// Only set up file logging if output file is specified
	if logFile != "" {
		// Create lumberjack logger for file output
		fileLogger := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28,    // days
			Compress:   false, // disabled by default
		}

		// Create multi-writer for both file and console output
		writer = NewMultiWriter(fileLogger, os.Stderr)
	} else {
		// Only use console output
		writer = os.Stderr
	}

	// Initialize the loggers
	LogCommon = log.New(writer, "", log.LstdFlags)
	LogDebug = log.New(writer, "DEBUG: ", log.LstdFlags)

	// Show mode status
	if OnceMode {
		color.Yellow("🔁 Once mode enabled - each SNI will be shown only once")
		// Start cleanup goroutine for seenSNIs
		startCleanup()
	}
	if Ja3Mode {
		color.Yellow("🔑 JA3 mode enabled - showing TLS fingerprints")
	}
	if JsonMode {
		color.Yellow("📝 JSON mode enabled - output will be in JSON format")
	}
}

// startCleanup starts a goroutine to periodically clean up the seenSNIs map
func startCleanup() {
	cleanupTicker = time.NewTicker(1 * time.Hour)
	cleanupDone = make(chan struct{})

	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				seenMutex.Lock()
				// Clear the map to prevent unbounded growth
				seenSNIs = make(map[string]int)
				seenMutex.Unlock()
				if VerboseMode {
					LogSystem.Println("Cleared seen SNIs cache")
				}
			case <-cleanupDone:
				cleanupTicker.Stop()
				return
			}
		}
	}()
}

// StopCleanup stops the cleanup goroutine
func StopCleanup() {
	if cleanupDone != nil {
		close(cleanupDone)
	}
}

// GetOutputFile returns the current log file path
func GetOutputFile() string {
	return outputFile
}

// IsVerbose returns true if verbose mode is enabled
func IsVerbose() bool {
	return VerboseMode
}

// MultiWriter is a custom writer that writes to multiple writers
type MultiWriter struct {
	writers []interface {
		Write([]byte) (int, error)
	}
}

// NewMultiWriter creates a new MultiWriter
func NewMultiWriter(writers ...interface {
	Write([]byte) (int, error)
}) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Write implements the io.Writer interface
func (mw *MultiWriter) Write(p []byte) (int, error) {
	for _, w := range mw.writers {
		w.Write(p)
	}
	return len(p), nil
}

// Printf formats and prints a message
func Printf(format string, v ...interface{}) {
	LogCommon.Printf(format, v...)
}

// Debugf formats and prints a debug message if verbose mode is enabled
func Debugf(format string, v ...interface{}) {
	if VerboseMode {
		LogDebug.Printf(format, v...)
	}
}

// Fatal formats and prints a fatal message
func Fatal(format string, v ...interface{}) {
	LogCommon.Fatalf(format, v...)
}

// PrintSNI formats and prints SNI information
func PrintSNI(srcIP, dstIP string, dstPort int, sni string, verified bool, seenCount int, packet *gopacket.Packet) {
	// Determine direction based on external IP
	direction := "in"
	if externalIP != "" {
		if srcIP == externalIP {
			direction = "out"
		}
	} else {
		// Fallback to IP comparison if external IP not available
		if srcIP < dstIP {
			direction = "out"
		}
	}

	// Skip if direction doesn't match configured direction
	if configuredDirection != "both" && direction != configuredDirection {
		return
	}

	// Track SNI count regardless of mode
	seenMutex.Lock()
	count := seenSNIs[sni] + 1
	seenSNIs[sni] = count
	seenMutex.Unlock()

	// In once mode, check if we've seen this SNI before
	if OnceMode {
		seenMutex.RLock()
		exists := seenSNIs[sni] > 1
		seenMutex.RUnlock()

		if exists {
			return // Skip if we've seen this SNI before
		}
	}

	// Get JA3 fingerprint if enabled
	ja3Hash := ""
	if Ja3Mode && packet != nil {
		ja3Hash = ja3.DigestHexPacket(*packet)
	}

	if JsonMode {
		// Create JSON event
		event := SNIEvent{
			Timestamp: time.Now().Format(time.RFC3339),
			SourceIP:  srcIP,
			DestIP:    dstIP,
			DestPort:  dstPort,
			SNI:       sni,
			Verified:  verified,
			SeenCount: count,
			Direction: direction,
		}
		if ja3Hash != "" {
			event.JA3 = ja3Hash
		}

		// Marshal to JSON
		jsonData, err := json.Marshal(event)
		if err != nil {
			LogCommon.Printf("Error marshaling JSON: %v", err)
			return
		}

		// Output JSON without timestamp prefix
		if outputFile != "" {
			LogCommon.SetFlags(0) // Remove timestamp prefix
			LogCommon.Println(string(jsonData))
			LogCommon.SetFlags(log.LstdFlags) // Restore flags
		} else {
			fmt.Println(string(jsonData))
		}
		return
	}

	// Format text message with optional JA3
	status := "SSL VERIFIED"
	if !verified {
		status = "Subject Mismatch"
	}
	message := fmt.Sprintf("SNI: %s -> %s:%d %s (%s) seen:%d dir:%s",
		srcIP, dstIP, dstPort, sni, status, count, direction)
	if ja3Hash != "" {
		message += fmt.Sprintf(" ja3:%s", ja3Hash)
	}

	// If output file is specified, log to file without color
	if outputFile != "" {
		LogCommon.Println(message)
	} else {
		// Otherwise, print to console with color
		if verified {
			color.Green(message)
		} else {
			color.Red(message)
		}
	}
}

// GetExternalIP returns the cached external IP
func GetExternalIP() string {
	return externalIP
}
