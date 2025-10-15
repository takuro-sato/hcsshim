# HvSocket Listener

A command-line tool to listen for and print messages sent by the `hvsocketDebug` function in the gcs-sidecar.

This tool listens on the same HvSocket service ID (`WindowsGcsSidecarDebugServiceID`) that the `hvsocketDebug` function in `cmd/gcs-sidecar/main.go` uses to send debug messages. It's useful for debugging and monitoring the messages sent by the gcs-sidecar service.

## Build

From the hcsshim root directory:

```powershell
go build .\internal\tools\hvsocketlistener
```

## Usage

```
hvsocketlistener [options]
```

Try `.\hvsocketlistener.exe -h` for options and example usages.
