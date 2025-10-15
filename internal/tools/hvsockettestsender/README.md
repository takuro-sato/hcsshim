# HvSocket Test Sender

A command-line tool to send test messages to the `hvsocketlistener` for local testing and debugging.

This tool sends messages to the same HvSocket service ID (`WindowsGcsSidecarDebugServiceID`) that the `hvsocketlistener` listens on. It's useful for:

- Testing the `hvsocketlistener` functionality locally
- Debugging HV socket connections
- Simulating the behavior of `hvsocketDebug` function in gcs-sidecar

## Build

From the hcsshim root directory:

```powershell
go build .\internal\tools\hvsockettestsender
```

## Usage

```
hvsockettestsender [options]
```

Try `.\hvsockettestsender.exe -h` for options and example usages.
