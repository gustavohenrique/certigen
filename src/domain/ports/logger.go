package ports

type Logger interface {
	StartCorrelationID() Logger
	WithFields() Logger
	Error(v ...interface{})
	Info(v ...interface{})
	Debug(v ...interface{})
	Fatal(v ...interface{})
}
