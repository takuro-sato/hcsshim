
# Get the list of changed files
$changedFiles = git diff --name-only | Where-Object { $_ -ne "" }

# Set source and destination root directories
$sourceRoot = "$PSScriptRoot"  # Current script directory (assumed repo root)
$destRoot = "U:\takuro\setup-cwcow\src\github.com\takuro-sato\hcsshim"

foreach ($file in $changedFiles) {
	$sourcePath = Join-Path $sourceRoot $file
	$destPath = Join-Path $destRoot $file

	# Ensure destination directory exists
	$destDir = Split-Path $destPath -Parent
	if (!(Test-Path $destDir)) {
		New-Item -ItemType Directory -Path $destDir -Force | Out-Null
	}

	# Copy the file
	Copy-Item -Path $sourcePath -Destination $destPath -Force
	Write-Host "Copied: $sourcePath -> $destPath"
}
