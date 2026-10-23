$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    dotnet build NetworkAccessManager.slnx -c Release --nologo
    if ($LASTEXITCODE -ne 0) { throw "Build failed." }

    dotnet test tests\NetworkAccessManager.Tests\NetworkAccessManager.Tests.csproj `
        -c Release --no-build --nologo --filter "Category!=Integration"
    if ($LASTEXITCODE -ne 0) { throw "Tests failed." }

    Write-Host ""
    Write-Host "Build and non-integration tests completed."
    Write-Host "Run: src\NetworkAccessManager.App\bin\Release\net10.0-windows\NetworkAccessManager.exe"
    Write-Host "Integration tests are skipped unless an elevated test host sets NAM_RUN_INTEGRATION_TESTS=1."
}
finally {
    Pop-Location
}
