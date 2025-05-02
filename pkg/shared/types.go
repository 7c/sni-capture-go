package shared

import (
	"log"
	"sync"
	"time"

	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket/layers"
)

var (
	Mutex1   sync.Mutex
	LogDebug *log.Logger
)

type Metadata struct {
	Identifier           string
	SourceIPPort         string
	Timestamp            string
	SourceIP             string
	SourceCC             string
	SourceASN            int
	SourceISP            string
	DestIP               string
	DestCC               string
	SourcePort           int
	SNI                  string
	Ready                bool
	Checksum1            string
	DataOffset           uint8
	JA3Fingerprint       string
	JA3FingerprintString string
	DestPort             int
	Sequence             uint32
	Tcp                  *layers.TCP
	Count                int
	ClientHello          *tlsx.ClientHelloBasic
	T                    time.Time
	Action               string
}

type LogData struct {
	Ip      string
	Request string
	Uagent  string
}

type MatchStorageEntry struct {
	T    time.Time
	Log  *LogData
	Meta *Metadata
}

var MatchStorage = make(map[string]MatchStorageEntry)
var Sessions = make(map[string]*Metadata)
