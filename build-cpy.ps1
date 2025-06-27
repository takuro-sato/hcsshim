go build -tags=rego .\cmd\containerd-shim-runhcs-v1\
go build -tags=rego .\cmd\gcs-sidecar\
cp .\containerd-shim-runhcs-v1.exe Y:\takuro\setup-uvm\bins\ -Force
cp .\gcs-sidecar.exe Y:\takuro\setup-uvm\bins\ -Force