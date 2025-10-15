//go:build windows
// +build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/gcs/prot"
)

func main() {
	var (
		vmid     = flag.String("vmid", "loopback", "VM ID to connect to (loopback, parent, children, or GUID)")
		message  = flag.String("message", "message from hvsockettestsender", "Message to send")
		count    = flag.Int("count", 1, "Number of times to send the message")
		interval = flag.Duration("interval", 1*time.Second, "Interval between messages")
		timeout  = flag.Duration("timeout", 10*time.Second, "Connection timeout")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -message=\"Hello World\"    # Send custom message\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -count=5 -interval=2s       # Send 5 messages, 2 seconds apart\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -vmid=parent -verbose       # Send to parent VM with verbose output\n", os.Args[0])
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

	hvsockAddr := &winio.HvsockAddr{
		VMID:      vmGUID,
		ServiceID: prot.WindowsGcsSidecarDebugServiceID,
	}

	if *verbose {
		fmt.Printf("Connecting to HvSocket: VMID=%s, ServiceID=%s\n", vmGUID, prot.WindowsGcsSidecarDebugServiceID)
		fmt.Printf("Will send %d message(s) with %v interval\n", *count, *interval)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Connect to the HV socket
	conn, err := winio.Dial(ctx, hvsockAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to HV socket: %v\n", err)
		fmt.Fprintf(os.Stderr, "Make sure hvsocketlistener is running with the same VM ID\n")
		os.Exit(1)
	}
	defer conn.Close()

	if *verbose {
		fmt.Printf("Successfully connected to HV socket\n")
	}

	// Send messages
	for i := 0; i < *count; i++ {
		var msgToSend string
		if *count > 1 {
			msgToSend = fmt.Sprintf("%s (message %d/%d)", *message, i+1, *count)
		} else {
			msgToSend = *message
		}

		if *verbose {
			fmt.Printf("Sending: %s\n", msgToSend)
		}

		_, err = conn.Write([]byte(msgToSend))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to socket: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Sent: %s\n", msgToSend)

		// Sleep between messages
		if i < *count-1 {
			if *verbose {
				fmt.Printf("Waiting %v before next message...\n", *interval)
			}
			time.Sleep(*interval)
		}
	}

	if *verbose {
		fmt.Printf("All messages sent successfully\n")
	}
}
