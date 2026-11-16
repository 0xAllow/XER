# Sign a Windows XER executable on Windows with a certificate available to SignTool.
# Run on an authorized signing workstation after building and before generating SHA256SUMS.
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Exe)) { throw 'Executable not found' }
if (-not (Get-Command signtool.exe -ErrorAction SilentlyContinue)) { throw 'Install Windows SDK SignTool' }
& signtool.exe sign /sha1 $CertificateThumbprint /fd SHA256 /tr https://timestamp.digicert.com /td SHA256 $Exe
if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed' }
& signtool.exe verify /pa /v $Exe
if ($LASTEXITCODE -ne 0) { throw 'Authenticode verification failed' }
Write-Output 'Authenticode signature verified.'
