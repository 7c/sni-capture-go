package shared

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ParseTCPMetadata(packet *gopacket.Packet, geoCountry *GeoIPClass, geoISP *GeoIPClass, ipLayer gopacket.Layer, createSession bool) *Metadata {
	meta := new(Metadata)
	meta.Checksum1 = "nomatch"
	meta.Count = 0
	meta.SNI = ""
	meta.Action = "none"
	meta.Timestamp = (*packet).Metadata().Timestamp.String()
	meta.T = time.Now()

	// Parse IP layer
	if ipLayer.LayerType() == layers.LayerTypeIPv4 {
		ip4, _ := ipLayer.(*layers.IPv4)
		meta.SourceIP = ip4.SrcIP.String()
		meta.DestIP = ip4.DstIP.String()
		if geoCountry != nil {
			meta.SourceCC = geoCountry.GetCountryCode(net.ParseIP(meta.SourceIP))
			meta.DestCC = geoCountry.GetCountryCode(net.ParseIP(meta.DestIP))
		}
		if geoISP != nil {
			if x := geoISP.GetISPRecord(net.ParseIP(meta.SourceIP)); x != nil {
				meta.SourceISP = x.ISP
				meta.SourceASN = x.AutonomousSystemNumber
			}
		}
	} else if ipLayer.LayerType() == layers.LayerTypeIPv6 {
		ip6, _ := ipLayer.(*layers.IPv6)
		meta.SourceIP = ip6.SrcIP.String()
		meta.DestIP = ip6.DstIP.String()
		if geoCountry != nil {
			meta.SourceCC = geoCountry.GetCountryCode(net.ParseIP(meta.SourceIP))
			meta.DestCC = geoCountry.GetCountryCode(net.ParseIP(meta.DestIP))
		}
	}

	// Parse TCP layer
	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		meta.SourcePort = int(tcp.SrcPort)
		meta.SourceIPPort = meta.SourceIP + ":" + tcp.SrcPort.String()
		meta.DestPort = int(tcp.DstPort)
		meta.Sequence = tcp.Seq
		meta.DataOffset = tcp.DataOffset
		meta.Tcp = tcp
	}

	// Create identifier
	meta.Identifier = fmt.Sprintf("%s:%d-%s:%d", meta.SourceIP, meta.SourcePort, meta.DestIP, meta.DestPort)

	// Create session if requested
	if createSession {
		Mutex1.Lock()
		if _, ok := Sessions[meta.Identifier]; !ok {
			Sessions[meta.Identifier] = meta
		} else {
			temp := Sessions[meta.Identifier]
			temp.Count = temp.Count + 1
			Sessions[meta.Identifier] = temp
		}
		Mutex1.Unlock()
		return Sessions[meta.Identifier]
	}

	return meta
}
