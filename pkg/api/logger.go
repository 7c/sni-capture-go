package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type APILogEntry struct {
	Timestamp    string            `json:"timestamp"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	ClientIP     string            `json:"client_ip"`
	ClientPort   string            `json:"client_port"`
	UserAgent    string            `json:"user_agent"`
	Headers      map[string]string `json:"headers"`
	RequestBody  interface{}       `json:"request_body,omitempty"`
	ResponseBody interface{}       `json:"response_body,omitempty"`
	StatusCode   int               `json:"status_code"`
}

type APILogger struct {
	writer io.Writer
}

func NewAPILogger(writer io.Writer) *APILogger {
	return &APILogger{writer: writer}
}

func (l *APILogger) LogRequest(r *http.Request, body interface{}) {
	entry := APILogEntry{
		Timestamp:   time.Now().Format(time.RFC3339),
		Method:      r.Method,
		Path:        r.URL.Path,
		ClientIP:    r.RemoteAddr,
		UserAgent:   r.UserAgent(),
		Headers:     make(map[string]string),
		RequestBody: body,
	}

	// Copy headers
	for k, v := range r.Header {
		entry.Headers[k] = v[0]
	}

	l.writeEntry(entry)
}

func (l *APILogger) LogResponse(r *http.Request, statusCode int, body interface{}) {
	entry := APILogEntry{
		Timestamp:    time.Now().Format(time.RFC3339),
		Method:       r.Method,
		Path:         r.URL.Path,
		ClientIP:     r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Headers:      make(map[string]string),
		ResponseBody: body,
		StatusCode:   statusCode,
	}

	// Copy headers
	for k, v := range r.Header {
		entry.Headers[k] = v[0]
	}

	l.writeEntry(entry)
}

func (l *APILogger) writeEntry(entry APILogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(l.writer, "Error marshaling log entry: %v\n", err)
		return
	}
	fmt.Fprintf(l.writer, "%s\n", string(data))
}
