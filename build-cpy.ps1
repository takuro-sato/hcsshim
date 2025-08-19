go build -tags=rego .\cmd\containerd-shim-runhcs-v1\
go build -tags=rego .\cmd\gcs-sidecar\
cp .\containerd-shim-runhcs-v1.exe X:\takuro\setup-cwcow\bins\ -Force
cp .\gcs-sidecar.exe X:\takuro\setup-cwcow\bins\ -Force