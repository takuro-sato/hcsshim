//go:build windows
// +build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/gcs/prot"
)

func main() {
	var (
		vmid    = flag.String("vmid", "loopback", "VM ID to listen on (loopback, parent, children, or GUID)")
		timeout = flag.Duration("timeout", 0, "Timeout for the listener (0 for no timeout)")
		verbose = flag.Bool("verbose", false, "Enable verbose output")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -vmid=children\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -timeout=30s\n", os.Args[0])
	}

	flag.Parse()

	// Parse VM ID
	var vmGUID guid.GUID
	switch *vmid {
	case "loopback":
		vmGUID = prot.HvGUIDLoopback
	case "parent":
		vmGUID = prot.HvGUIDParent
	case "children":
		vmGUID = prot.HvGUIDChildren
	default:
		// Try to parse as GUID
		parsedGUID, err := guid.FromString(*vmid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid VM ID '%s'. Use 'loopback', 'parent', 'children', or a valid GUID\n", *vmid)
			os.Exit(1)
		}
		vmGUID = parsedGUID
	}

	// Create HV socket address
	hvsockAddr := &winio.HvsockAddr{
		VMID:      vmGUID,
		ServiceID: prot.WindowsGcsSidecarDebugServiceID,
	}

	if *verbose {
		fmt.Printf("Listening on HvSocket: VMID=%s, ServiceID=%s\n", vmGUID, prot.WindowsGcsSidecarDebugServiceID)
	}

	// Create listener
	listener, err := winio.ListenHvsock(hvsockAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HV socket listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("HvSocket Listener started. Waiting for connections...\n")
	if *timeout > 0 {
		fmt.Printf("Will timeout after %v\n", *timeout)
	}
	fmt.Printf("Press Ctrl+C to stop\n\n")

	// Setup context for timeout and signal handling
	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	// TODO: Not sure which is actually needed for ctl+C in windows.
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Channel to signal when we should exit
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)

		for {
			select {
			case <-ctx.Done():
				if *verbose {
					fmt.Printf("Context cancelled: %v\n", ctx.Err())
				}
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						// Context was cancelled, exit gracefully
						return
					default:
						if *verbose {
							fmt.Printf("Error accepting connection: %v\n", err)
						}
						continue
					}
				}

				if *verbose {
					fmt.Printf("New connection accepted at %s\n", time.Now().Format("15:04:05.000"))
				}

				go handleConnection(conn, *verbose)
			}
		}
	}()

	select {
	case <-sigCh:
		fmt.Printf("\nReceived interrupt signal. Shutting down...\n")
	case <-ctx.Done():
		fmt.Printf("\nTimeout reached. Shutting down...\n")
	case <-doneCh:
		fmt.Printf("\nListener stopped.\n")
	}
}

func handleConnection(conn io.ReadWriteCloser, verbose bool) {
	defer conn.Close()

	if verbose {
		fmt.Printf("Handling connection...\n")
	}

	// Read messages from the connection
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF && verbose {
				fmt.Printf("Error reading from connection: %v\n", err)
			}
			break
		}

		if n > 0 {
			message := string(buffer[:n])
			timestamp := time.Now().Format("2006-01-02 15:04:05.000")
			fmt.Printf("[%s] %s\n", timestamp, message)
		}
	}
}
