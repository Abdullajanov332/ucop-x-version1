package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	target := flag.String("target", "", "Target host to scan")
	ports := flag.String("ports", "80,443,8080", "Comma-separated ports")
	timeout := flag.Duration("timeout", 3*time.Second, "Connection timeout")
	verbose := flag.Bool("verbose", false, "Verbose output")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: scanner -target <host> [-ports 80,443] [-timeout 3s]")
		os.Exit(1)
	}

	fmt.Printf("UCOP-X Scanner - Target: %s, Ports: %s, Timeout: %v\n",
		*target, *ports, *timeout)

	portList := parsePorts(*ports)
	results := make(chan ScanResult, len(portList))

	for _, port := range portList {
		go scanPort(*target, port, *timeout, *verbose, results)
	}

	openPorts := 0
	closedPorts := 0
	for range portList {
		r := <-results
		if r.Open {
			fmt.Printf("  OPEN  %s:%-5d (%s)\n", *target, r.Port, r.Service)
			openPorts++
		} else if *verbose {
			fmt.Printf("  CLOSED %s:%-5d\n", *target, r.Port)
			closedPorts++
		}
	}

	fmt.Printf("\nScan complete: %d open, %d closed\n", openPorts, closedPorts)
}

func parsePorts(ports string) []int {
	var result []int
	current := 0
	for _, c := range ports {
		if c >= '0' && c <= '9' {
			current = current*10 + int(c-'0')
		} else if c == ',' {
			result = append(result, current)
			current = 0
		}
	}
	result = append(result, current)
	return result
}
