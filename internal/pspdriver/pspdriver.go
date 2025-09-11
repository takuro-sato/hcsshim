//go:build windows
// +build windows

package pspdriver

import (
	"context"
	"time"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName            = "AmdSnpPsp"
	snpFirmwareEnvVariable = "SnpGuestReport"
	privilegeName          = "SeSystemEnvironmentPrivilege"
	amdSevSnpGUIDStr       = "{4c3bddb9-c2b1-4cbd-9e0c-cb45e9e0e168}"
)

const (
	SNPPSP_API_STATUS_SUCCESS              = 0x00000000
	SNPPSP_API_STATUS_UNSUCCESSFUL         = 0x00000001
	SNPPSP_API_STATUS_DRIVER_UNSUCCESSFUL  = 0x00000003
	SNPPSP_API_STATUS_PSP_UNSUCCESSFUL     = 0x00000004
	SNPPSP_API_STATUS_INVALID_PARAMETER    = 0x00000005
	SNPPSP_API_STATUS_DEVICE_NOT_AVAILABLE = 0x00000006
)

var (
	amdsnppspapi = windows.NewLazySystemDLL("amdsnppspapi.dll")
	// It will panic if the function is not found when .Call() is called.
	isSnpModeProc              = amdsnppspapi.NewProc("SnpPspIsSnpMode")
	fetchAttestationReportProc = amdsnppspapi.NewProc("SnpPspFetchAttestationReport")
	pspDriverStarted           = false
	// The error needs to be stored to be retrieved later.
	// When driver or its dll fails, we keep gcs-sidecar running and
	// return "deny" for any requests for the sidecar.
	// The error message will be returned to the host.
	pspDriverError error = nil
)

func StartPSPDriver(ctx context.Context) error {
	// Connect to the Service Control Manager
	m, err := mgr.Connect()
	if err != nil {
		return errors.Wrap(err, "Failed to connect to service manager")
	}
	defer m.Disconnect()

	// Open the service
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errors.Wrapf(err, "Could not access service %q", serviceName)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil {
		return errors.Wrapf(err, "Could not start service %q", serviceName)
	}

	// From the documentation, there is no guarantee that the service will be
	// in `Running` state immediately after starting it.
	// Wait until the service is in the `Running` state.
	timeout := time.After(3 * time.Second)
	tick := time.Tick(100 * time.Millisecond)
	for {
		select {
		case <-timeout:
			pspDriverError = errors.New("timed out waiting for PSP driver to start")
			return pspDriverError
		case <-tick:
			status, err := s.Query()
			if err != nil {
				pspDriverError = errors.Wrap(err, "could not query PSP driver status")
				return pspDriverError
			}
			if status.State == svc.Running {
				log.G(ctx).Tracef("Service %q started successfully", serviceName)

				pspDriverStarted = true
				return nil
				// log.G(ctx).Tracef("Simulating PSP driver error 2")
				// // Testing the case when psp driver fails to start
				// pspDriverError = errors.New("Simulating PSP driver error")
				// return pspDriverError
			}
		}
	}
}

func IsPspDriverStarted() bool {
	return pspDriverStarted
}

// Return an error from the PSP driver dll
// when it fails to use the dll at all.
// Otherwise it returns nil.
func GetPspDriverError() error {
	return pspDriverError
}

// IsSNPMode() returns true if it's in SNP mode.
func IsSNPMode(ctx context.Context) (bool, error) {

	if pspDriverError != nil {
		return false, pspDriverError
	}

	if !pspDriverStarted {
		return false, errors.New("PSP driver is not started")
	}

	// snpMode is defined as BOOLEAN (= byte)
	var snpMode uint8
	ret, _, _ := isSnpModeProc.Call(uintptr(unsafe.Pointer(&snpMode)))
	if ret != SNPPSP_API_STATUS_SUCCESS {
		pspDriverError = errors.Errorf("failed to determine if it's in SNP VM. SNPPSP_API_STATUS: 0x%x", ret)
		return false, pspDriverError
	}

	return snpMode == 1, nil
}
