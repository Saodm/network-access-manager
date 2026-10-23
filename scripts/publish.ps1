$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "dist\NetworkAccessManager"
Push-Location $root
try {
    if (Test-Path $out) {
        Remove-Item -LiteralPath $out -Recurse -Force
    }

    dotnet publish src\NetworkAccessManager.App\NetworkAccessManager.App.csproj `
        -c Release --nologo --no-self-contained -o $out
    if ($LASTEXITCODE -ne 0) { throw "Publish failed." }

    Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination (Join-Path $out "README.md") -Force
    Copy-Item -LiteralPath (Join-Path $root "CHANGELOG.md") -Destination (Join-Path $out "CHANGELOG.md") -Force
    New-Item -ItemType Directory -Path (Join-Path $out "docs") -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $root "docs\VERIFICATION.md") -Destination (Join-Path $out "docs\VERIFICATION.md") -Force
    Copy-Item -LiteralPath (Join-Path $root "docs\verification-system-verifier.txt") -Destination (Join-Path $out "docs\verification-system-verifier.txt") -Force
    Copy-Item -LiteralPath (Join-Path $root "docs\screenshots") -Destination (Join-Path $out "docs\screenshots") -Recurse -Force

    $zip = Join-Path $root "dist\NetworkAccessManager-win-x64.zip"
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -LiteralPath $out -DestinationPath $zip -CompressionLevel Optimal

    Remove-Item -LiteralPath (Join-Path $out "data") -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Published: $out"
    Write-Host "Archive:   $zip"
}
finally {
    Pop-Location
}
