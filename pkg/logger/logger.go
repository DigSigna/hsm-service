package logger

import (
    "go.uber.org/zap"
)

// Logger interface for application logging
type Logger interface {
    Info(msg string, fields ...zap.Field)
    Error(msg string, fields ...zap.Field)
    Debug(msg string, fields ...zap.Field)
    Warn(msg string, fields ...zap.Field)
    Sync() error
}

// ZapLogger implements Logger using zap
type ZapLogger struct {
    logger *zap.Logger
}

// NewZapLogger creates a new zap logger
func NewZapLogger(environment string) *ZapLogger {
    var zapLogger *zap.Logger
    var err error

    if environment == "production" {
        zapLogger, err = zap.NewProduction()
    } else {
        zapLogger, err = zap.NewDevelopment()
    }

    if err != nil {
        panic("failed to create logger: " + err.Error())
    }

    return &ZapLogger{logger: zapLogger}
}

// Info logs info level messages
func (l *ZapLogger) Info(msg string, fields ...zap.Field) {
    l.logger.Info(msg, fields...)
}

// Error logs error level messages
func (l *ZapLogger) Error(msg string, fields ...zap.Field) {
    l.logger.Error(msg, fields...)
}

// Debug logs debug level messages
func (l *ZapLogger) Debug(msg string, fields ...zap.Field) {
    l.logger.Debug(msg, fields...)
}

// Warn logs warn level messages
func (l *ZapLogger) Warn(msg string, fields ...zap.Field) {
    l.logger.Warn(msg, fields...)
}

// Sync flushes any buffered log entries
func (l *ZapLogger) Sync() error {
    return l.logger.Sync()
}