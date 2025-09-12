//go:build windows
// +build windows

package pspdriver

import (
	"bytes"
	"context"
	"fmt"
	"os"
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

// TODO: These constants are duplicated (and slightly different) with pkg/amdsevsnp

const (
	SNPPSP_API_REPORT_DATA_SIZE                    = 64
	SNPPSP_API_ATTESTATION_REPORT_SIZE             = 0x4A0
	SNPPSP_API_REPORT_CURRENT_TCB_SIZE             = 8
	SNPPSP_API_REPORT_MEASUREMENT_SIZE             = 48
	SNPPSP_API_REPORT_HOST_DATA_SIZE               = 32
	SNPPSP_API_REPORT_ID_KEY_DIGEST_SIZE           = 48
	SNPPSP_API_REPORT_AUTHOR_KEY_DIGEST_SIZE       = 48
	SNPPSP_API_REPORT_SNPPSP_API_REPORT_ID_SIZE    = 32
	SNPPSP_API_REPORT_SNPPSP_API_REPORT_ID_MA_SIZE = 32
	SNPPSP_API_REPORT_REPORTED_TCB_SIZE            = 8
	SNPPSP_API_REPORT_RESERVED2_SIZE               = 21
	SNPPSP_API_REPORT_CHIP_ID_SIZE                 = 64
	SNPPSP_API_REPORT_COMMITTED_TCB_SIZE           = 8
	SNPPSP_API_REPORT_LAUNCH_TCB_SIZE              = 8
	SNPPSP_API_REPORT_RESERVED5_SIZE               = 168
	SNPPSP_API_REPORT_SIGNATURE_SIZE               = 512
)

type SNPPSPUINT128 struct {
	Lo uint64
	Hi uint64
}

type SNPPSPGuestRequestResult struct {
	DriverStatus uint32
	PspStatus    uint64
}

type SNPAttestationReport struct {
	Version         uint32
	GuestSvn        uint32
	Policy          uint64
	FamilyId        SNPPSPUINT128
	ImageId         SNPPSPUINT128
	Vmpl            uint32
	SignatureAlgo   uint32
	CurrentTcb      [SNPPSP_API_REPORT_CURRENT_TCB_SIZE]uint8
	PlatformInfo    uint64
	AuthorKeyEn     uint32
	Reserved1       uint32
	ReportData      [SNPPSP_API_REPORT_DATA_SIZE]uint8
	Measurement     [SNPPSP_API_REPORT_MEASUREMENT_SIZE]uint8
	HostData        [SNPPSP_API_REPORT_HOST_DATA_SIZE]uint8
	IdKeyDigest     [SNPPSP_API_REPORT_ID_KEY_DIGEST_SIZE]uint8
	AuthorKeyDigest [SNPPSP_API_REPORT_AUTHOR_KEY_DIGEST_SIZE]uint8
	ReportId        [SNPPSP_API_REPORT_SNPPSP_API_REPORT_ID_SIZE]uint8
	ReportIdMa      [SNPPSP_API_REPORT_SNPPSP_API_REPORT_ID_MA_SIZE]uint8
	ReportedTcb     [SNPPSP_API_REPORT_REPORTED_TCB_SIZE]uint8
	CpuidFamId      uint8
	CpuidModId      uint8
	CpuidStep       uint8
	Reserved2       [SNPPSP_API_REPORT_RESERVED2_SIZE]uint8
	ChipId          [SNPPSP_API_REPORT_CHIP_ID_SIZE]uint8
	CommittedTcb    [SNPPSP_API_REPORT_COMMITTED_TCB_SIZE]uint8
	CurrentBuild    uint8
	CurrentMinor    uint8
	CurrentMajor    uint8
	Reserved3       uint8
	CommittedBuild  uint8
	CommittedMinor  uint8
	CommittedMajor  uint8
	Reserved4       uint8
	LaunchTcb       [SNPPSP_API_REPORT_LAUNCH_TCB_SIZE]uint8
	Reserved5       [SNPPSP_API_REPORT_RESERVED5_SIZE]uint8
	Signature       [SNPPSP_API_REPORT_SIGNATURE_SIZE]uint8
}

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

// TODO: Should we use ctx for functions here?

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

// FetchRawSNPReport returns attestation report bytes.
func FetchRawSNPReport(reportData []byte) ([]byte, error) {
	if pspDriverError != nil {
		return nil, pspDriverError
	}

	if !pspDriverStarted {
		return nil, errors.New("PSP driver is not started")
	}

	var reportDataBuf [SNPPSP_API_REPORT_DATA_SIZE]uint8

	if reportData != nil {
		if len(reportData) > SNPPSP_API_REPORT_DATA_SIZE {
			return nil, fmt.Errorf("reportData too large: %s", reportData)
		}
		copy(reportDataBuf[:], reportData)
	}

	var report [SNPPSP_API_ATTESTATION_REPORT_SIZE]uint8
	var guestRequestResult SNPPSPGuestRequestResult

	// Fetch attestation report
	ret, _, _ := fetchAttestationReportProc.Call(
		uintptr(unsafe.Pointer(&reportDataBuf[0])),
		uintptr(unsafe.Pointer(&guestRequestResult)),
		uintptr(unsafe.Pointer(&report[0])))

	if ret != SNPPSP_API_STATUS_SUCCESS {
		fmt.Printf("Failed to fetch attestation report. res: 0x%x, DriverStatus: 0x%x, PspStatus: 0x%x\n",
			ret, guestRequestResult.DriverStatus, guestRequestResult.PspStatus)
		os.Exit(1)
	}

	// reportStruct := (*SNPAttestationReport)(unsafe.Pointer(&report[0]))
	return report[:], nil
}

// FetchParsedSNPReport parses raw attestation response into proper structs.
func FetchParsedSNPReport(reportData []byte) (SNPAttestationReport, error) {
	rawBytes, err := FetchRawSNPReport(reportData)
	if err != nil {
		return SNPAttestationReport{}, err
	}

	if len(rawBytes) != SNPPSP_API_ATTESTATION_REPORT_SIZE {
		return SNPAttestationReport{}, fmt.Errorf("invalid attestation report size: %d", len(rawBytes))
	}

	reportStruct := (*SNPAttestationReport)(unsafe.Pointer(&rawBytes[0]))
	return *reportStruct, nil
}

// TODO: Based on internal\guest\runtime\hcsv2\hostdata.go and it's duplicated.
// ValidateHostData fetches SNP report (if applicable) and validates `hostData` against
// HostData set at UVM launch.
func ValidateHostData(ctx context.Context, hostData []byte) error {
	// TODO: These checks are duplicated in IsSNPMode().
	// "We can optimize it" vs "We should be explicit".
	if pspDriverError != nil {
		return pspDriverError
	}

	if !pspDriverStarted {
		return errors.New("PSP driver is not started")
	}

	// If the UVM is not SNP, then don't try to fetch an SNP report.
	isSnpMode, err := IsSNPMode(ctx)
	if err != nil {
		return err
	}
	if !isSnpMode {
		return nil
	}
	report, err := FetchParsedSNPReport(nil)
	if err != nil {
		return err
	}

	log.G(ctx).Tracef("TAKURO_TEST: security policy digest: %q, HostData provided at launch %q",
		hostData,
		report.HostData[:])

	if !bytes.Equal(hostData, report.HostData[:]) {
		return fmt.Errorf(
			"security policy digest %q doesn't match HostData provided at launch %q",
			hostData,
			report.HostData[:],
		)
	}

	return nil
}
