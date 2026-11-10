package log // import "github.com/xtls/xray-core/common/log"

import (
	"sync/atomic"

	"github.com/xtls/xray-core/common/serial"
)

// Message is the interface for all log messages.
type Message interface {
	String() string
}

// Handler is the interface for log handler.
type Handler interface {
	Handle(msg Message)
}

// GeneralMessage is a general log message that can contain all kind of content.
type GeneralMessage struct {
	Severity Severity
	Content  interface{}
}

// String implements Message.
func (m *GeneralMessage) String() string {
	return serial.Concat("[", m.Severity, "] ", m.Content)
}

// Record writes a message into log stream.
func Record(msg Message) {
	if h := logHandler.Load(); h != nil {
		(*h).Handle(msg)
	}
}

type SeverityLogger interface {
	Handler
	Severity() Severity
}

func GetSeverity() Severity {
	if h := logHandler.Load(); h != nil {
		if sh, ok := (*h).(SeverityLogger); ok {
			return sh.Severity()
		}
	}
	// log everything by default
	return Severity_Debug
}

var logHandler atomic.Pointer[Handler]

// minSeverity is the lowest severity that will be processed. Log calls below it return early.
var minSeverity = int32(Severity_Debug)

// SetMinSeverity sets the minimum severity that will be processed. Messages with a higher
// severity value (less severe) are silently dropped at the source.
func SetMinSeverity(severity Severity) {
	atomic.StoreInt32(&minSeverity, int32(severity))
}

// IsSeverityEnabled reports whether messages of the given severity will be processed.
func IsSeverityEnabled(severity Severity) bool {
	return severity <= Severity(atomic.LoadInt32(&minSeverity))
}

// RegisterHandler registers a new handler as current log handler. Previous registered handler will be discarded.
func RegisterHandler(handler Handler) {
	if handler == nil {
		panic("Log handler is nil")
	}
	logHandler.Store(&handler)
}
