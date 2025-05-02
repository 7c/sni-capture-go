package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type SNIData struct {
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

type APIResponse struct {
	RetCode int         `json:"retcode"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type Server struct {
	router     *chi.Mux
	host       string
	port       int
	logFile    string
	uniqueSNIs map[string]SNIData
	recentSNIs []SNIData
	mutex      sync.RWMutex
}

// GetHost returns the server's host address
func (s *Server) GetHost() string {
	return s.host
}

// GetPort returns the server's port
func (s *Server) GetPort() int {
	return s.port
}

// GetLogFile returns the server's log file path
func (s *Server) GetLogFile() string {
	return s.logFile
}

func NewServer(host string, port int, logFile string) *Server {
	s := &Server{
		router:     chi.NewRouter(),
		host:       host,
		port:       port,
		logFile:    logFile,
		uniqueSNIs: make(map[string]SNIData),
		recentSNIs: make([]SNIData, 0),
	}

	// Setup middleware
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.Timeout(60 * time.Second))

	// Setup routes
	s.router.Get("/api/ping", s.handlePing)
	s.router.Get("/api/snis/unique", s.handleUniqueSNIs)
	s.router.Get("/api/snis/{minutes}", s.handleRecentSNIs)

	// Start cleanup goroutine
	go s.cleanupRecentSNIs()

	return s
}

func (s *Server) Start() error {
	addr := s.host + ":" + strconv.Itoa(s.port)
	return http.ListenAndServe(addr, s.router)
}

func (s *Server) AddSNI(data SNIData) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Add to unique SNIs
	s.uniqueSNIs[data.SNI] = data

	// Add to recent SNIs
	s.recentSNIs = append(s.recentSNIs, data)
}

func (s *Server) cleanupRecentSNIs() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.mutex.Lock()
		// Keep only last 10 minutes of data
		cutoff := time.Now().Add(-10 * time.Minute)
		newRecent := make([]SNIData, 0)
		for _, sni := range s.recentSNIs {
			t, _ := time.Parse(time.RFC3339, sni.Timestamp)
			if t.After(cutoff) {
				newRecent = append(newRecent, sni)
			}
		}
		s.recentSNIs = newRecent
		s.mutex.Unlock()
	}
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, APIResponse{RetCode: 200})
}

func (s *Server) handleUniqueSNIs(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	snis := make([]SNIData, 0, len(s.uniqueSNIs))
	for _, sni := range s.uniqueSNIs {
		snis = append(snis, sni)
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		RetCode: 200,
		Data: struct {
			SNIs  []SNIData `json:"snis"`
			Count int       `json:"count"`
		}{
			SNIs:  snis,
			Count: len(snis),
		},
	})
}

func (s *Server) handleRecentSNIs(w http.ResponseWriter, r *http.Request) {
	minutesStr := chi.URLParam(r, "minutes")
	minutes, err := strconv.Atoi(minutesStr)
	if err != nil || minutes < 1 || minutes > 10 {
		s.writeJSON(w, http.StatusBadRequest, APIResponse{
			RetCode: 400,
			Error:   "minutes must be between 1 and 10",
		})
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)
	recent := make([]SNIData, 0)

	for _, sni := range s.recentSNIs {
		t, _ := time.Parse(time.RFC3339, sni.Timestamp)
		if t.After(cutoff) {
			recent = append(recent, sni)
		}
	}

	s.writeJSON(w, http.StatusOK, APIResponse{
		RetCode: 200,
		Data: struct {
			SNIs  []SNIData `json:"snis"`
			Count int       `json:"count"`
		}{
			SNIs:  recent,
			Count: len(recent),
		},
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
