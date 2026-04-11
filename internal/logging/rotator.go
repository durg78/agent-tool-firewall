package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rotator handles log file rotation
type Rotator struct {
	mu             sync.Mutex
	basePath       string
	maxSizeBytes   int64
	maxBackups     int
	maxAgeDays     int
	compress       bool
	currentSize    int64
	file           *os.File
}

// Config for log rotation
type Config struct {
	// Path to the log file (e.g., "logs/atf-audit.log")
	Path string

	// Maximum size in bytes before rotation (default: 100MB)
	MaxSizeBytes int64

	// Maximum number of backup files to keep (default: 5)
	MaxBackups int

	// Maximum age in days before deletion (default: 30)
	MaxAgeDays int

	// Whether to compress rotated logs (default: true)
	Compress bool
}

// NewRotator creates a new log rotator
func NewRotator(cfg Config) (*Rotator, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("log path required")
	}

	// Set defaults
	if cfg.MaxSizeBytes == 0 {
		cfg.MaxSizeBytes = 100 * 1024 * 1024 // 100MB
	}
	if cfg.MaxBackups == 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays == 0 {
		cfg.MaxAgeDays = 30
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	r := &Rotator{
		basePath:     cfg.Path,
		maxSizeBytes: cfg.MaxSizeBytes,
		maxBackups:   cfg.MaxBackups,
		maxAgeDays:   cfg.MaxAgeDays,
		compress:     cfg.Compress,
	}

	// Open or create the log file
	if err := r.openFile(); err != nil {
		return nil, err
	}

	// Get current file size
	if info, err := r.file.Stat(); err == nil {
		r.currentSize = info.Size()
	}

	// Clean up old backups
	r.cleanupOldBackups()

	return r, nil
}

// openFile opens the current log file
func (r *Rotator) openFile() error {
	file, err := os.OpenFile(r.basePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	r.file = file
	return nil
}

// Write implements io.Writer
func (r *Rotator) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if rotation is needed
	if r.currentSize+int64(len(p)) > r.maxSizeBytes {
		if err := r.rotate(); err != nil {
			log.Printf("Log rotation failed: %v", err)
			// Continue writing even if rotation fails
		}
	}

	// Write to file
	n, err = r.file.Write(p)
	if err == nil {
		r.currentSize += int64(n)
	}

	return n, err
}

// Close closes the log file
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// rotate performs log rotation
func (r *Rotator) rotate() error {
	// Close current file
	if err := r.file.Close(); err != nil {
		return fmt.Errorf("failed to close log file: %w", err)
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("2006-01-02-15-04-05")
	backupPath := fmt.Sprintf("%s.%s", r.basePath, timestamp)

	// Rename current file to backup
	if err := os.Rename(r.basePath, backupPath); err != nil {
		// Try to reopen the file if rename fails
		_ = r.openFile()
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	log.Printf("Log rotated to: %s", backupPath)

	// Compress if enabled
	if r.compress {
		go r.compressFile(backupPath)
	}

	// Open new log file
	if err := r.openFile(); err != nil {
		return err
	}

	r.currentSize = 0

	// Clean up old backups
	go r.cleanupOldBackups()

	return nil
}

// compressFile compresses a rotated log file
func (r *Rotator) compressFile(path string) {
	// Simple gzip compression
	// Note: For production, consider using a proper compression library
	// This is a placeholder - actual implementation would use compress/gzip
	compressedPath := path + ".gz"

	// For now, just rename to indicate it's archived
	// In production, implement proper gzip compression
	if err := os.Rename(path, compressedPath); err != nil {
		log.Printf("Failed to compress log file %s: %v", path, err)
	}
}

// cleanupOldBackups removes old backup files
func (r *Rotator) cleanupOldBackups() {
	r.mu.Lock()
	defer r.mu.Unlock()

	pattern := r.basePath + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Sort by modification time (oldest first)
	type fileInfo struct {
		path string
		mtime time.Time
	}
	var files []fileInfo

	for _, path := range matches {
		if info, err := os.Stat(path); err == nil {
			files = append(files, fileInfo{path: path, mtime: info.ModTime()})
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].mtime.Before(files[j].mtime)
	})

	// Remove old files based on age
	now := time.Now()
	maxAge := time.Duration(r.maxAgeDays) * 24 * time.Hour

	for i, file := range files {
		// Check age
		if now.Sub(file.mtime) > maxAge {
			if err := os.Remove(file.path); err != nil {
				log.Printf("Failed to remove old log file %s: %v", file.path, err)
			} else {
				log.Printf("Removed old log file: %s", file.path)
			}
			continue
		}

		// Check count (keep only maxBackups)
		if i < len(files)-r.maxBackups {
			if err := os.Remove(file.path); err != nil {
				log.Printf("Failed to remove old log file %s: %v", file.path, err)
			} else {
				log.Printf("Removed old log file: %s", file.path)
			}
		}
	}
}

// ParseLogFilePath extracts the base path and extension
func ParseLogFilePath(path string) (base string, ext string) {
	// Handle .gz extension
	if strings.HasSuffix(path, ".gz") {
		path = strings.TrimSuffix(path, ".gz")
		ext = ".gz"
	}

	// Find the last dot to separate extension
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 {
		return path, ""
	}

	return path[:lastDot], path[lastDot:]
}

// GetLogFileSize returns the size of the current log file
func GetLogFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// LogWriter wraps a rotator to provide standard log.Logger
func LogWriter(r *Rotator) *log.Logger {
	return log.New(r, "", 0)
}
