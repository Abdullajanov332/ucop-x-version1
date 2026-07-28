package main

import (
	"fmt"
	"net"
	"time"
)

type ScanResult struct {
	Port    int
	Open    bool
	Service string
}

func scanPort(host string, port int, timeout time.Duration, verbose bool, results chan<- ScanResult) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if conn != nil {
		conn.Close()
	}

	service := portToService(port)
	results <- ScanResult{
		Port:    port,
		Open:    err == nil,
		Service: service,
	}
}

func portToService(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		27017: "MongoDB",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}
