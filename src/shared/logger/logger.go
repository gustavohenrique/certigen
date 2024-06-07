package logger

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"certigen/src/domain/ports"
)

var globalInstance *Log
var (
	APP_NAME    = ""
	BUILD_DATE  = time.Now().UTC().Format("2006-01-02 15:04:05")
	COMMIT_HASH = "local"
)

type Config struct {
	Level      string
	Output     string
	Format     string
	PrettyJSON bool
}

type metadata struct {
	hostname      string
	pid           int
	goVersion     string
	correlationID string
}

type Log struct {
	log      *logrus.Logger
	logEntry *logrus.Entry
	config   Config
	metadata metadata
}

func New(config Config) ports.Logger {
	return Init(config)
}

func Init(config Config) ports.Logger {
	log := logrus.New()
	out := config.Output
	if out == "" || out == "stdout" {
		log.SetOutput(os.Stdout)
	} else {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			panic(err)
		}
		log.SetOutput(f)
	}

	var formatter logrus.Formatter
	format := config.Format
	if format == "" || format == "text" {
		formatter = &logrus.TextFormatter{}
	}

	if format == "json" {
		formatter = &logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFile:  "file",
			},
			TimestampFormat: "2006-01-02 15:04:05",
			PrettyPrint:     config.PrettyJSON,
		}
	}

	level := getLogLevel(config)
	log.SetLevel(level)

	hostname, _ := os.Hostname()
	log.SetFormatter(formatter)
	instance := &Log{
		log:    log,
		config: config,
	}
	instance.metadata.hostname = hostname
	instance.metadata.pid = os.Getpid()
	instance.metadata.goVersion = runtime.Version()
	singleton(instance)
	return instance
}

func Get() ports.Logger {
	if globalInstance != nil {
		return globalInstance
	}
	return New(Config{})
}

func (l *Log) Error(v ...interface{}) {
	message := l.toString(v)
	if l.logEntry != nil {
		l.logEntry.Error(message)
		return
	}
	l.log.WithField("caller", getCaller()).Error(message)
}

func (l *Log) Info(v ...interface{}) {
	message := l.toString(v)
	if l.logEntry != nil {
		l.logEntry.Info(message)
		return
	}
	l.log.Info(message)
}

func (l *Log) Debug(v ...interface{}) {
	message := l.toString(v)
	l.log.Debug(message)
}

func (l *Log) Fatal(v ...interface{}) {
	message := l.toString(v)
	if l.logEntry != nil {
		l.logEntry.Error(message)
		return
	}
	l.log.WithField("func", getCaller()).Fatal(message)
}

func (l *Log) toString(v ...interface{}) string {
	var buf bytes.Buffer
	for _, s := range v {
		buf.WriteString(fmt.Sprintf("%+v", s))
	}
	value := strings.Replace(buf.String(), "[", "", 1)
	value = strings.Replace(value, "]", "", 1)

	level := getLogLevel(l.config)
	if level.String() == "debug" {
		value = concatDebugInfo(value)
	}

	return value
}

func (l *Log) StartCorrelationID() ports.Logger {
	l.metadata.correlationID = generateBase58CorrelationID()
	return l
}

func (l *Log) WithFields() ports.Logger {
	_, file, line, _ := runtime.Caller(1)
	parts := strings.Split(file, "/")
	filename := parts[len(parts)-1]
	l.logEntry = l.log.
		WithField("file", filename).
		WithField("line", fmt.Sprintf("%d", line)).
		WithField("caller", fmt.Sprintf("%s:%d", filename, line)).
		WithField("application", APP_NAME).
		WithField("build_date_utc", BUILD_DATE).
		WithField("commit_hash", COMMIT_HASH).
		WithField("hostname", l.metadata.hostname).
		WithField("go_version", l.metadata.goVersion).
		WithField("correlation_id", l.metadata.correlationID).
		WithField("pid", fmt.Sprintf("%d", l.metadata.pid))
	return l
}

func getCaller() string {
	pc, _, _, ok := runtime.Caller(2)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		_, line := details.FileLine(pc)
		return fmt.Sprintf("func:%s line:%d", details.Name(), line)
	}
	return ""
}

func concatDebugInfo(value string) string {
	pc, file, line, ok := runtime.Caller(3)
	if !ok {
		file = "?"
		line = 0
	}

	fn := runtime.FuncForPC(pc)
	var fnName string
	if fn == nil {
		fnName = "?"
	} else {
		dotName := filepath.Ext(fn.Name())
		fnName = strings.TrimLeft(dotName, ".")
	}

	return fmt.Sprintf("%s:%d %s: %s", filepath.Base(file), line, fnName, value)
}

func getLogLevel(config Config) logrus.Level {
	level := config.Level
	if lvl, err := logrus.ParseLevel(level); err == nil {
		return lvl
	}
	return logrus.ErrorLevel
}

func singleton(instance *Log) {
	var once sync.Once
	once.Do(func() {
		globalInstance = instance
	})
}

func generateBase58CorrelationID() string {
	const (
		alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
		size     = 11
	)

	var id = make([]byte, size)
	if _, err := crand.Read(id); err != nil {
		panic(err)
	}
	for i, p := range id {
		id[i] = alphabet[int(p)%len(alphabet)]
	}
	return string(id)
}
