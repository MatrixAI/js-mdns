function Save-ChocoPackage {
  param (
      $PackageName
  )
  Rename-Item -Path "$env:ChocolateyInstall\lib\$PackageName\$PackageName.nupkg" -NewName "$PackageName.nupkg.zip" -ErrorAction:SilentlyContinue
  Expand-Archive -LiteralPath "$env:ChocolateyInstall\lib\$PackageName\$PackageName.nupkg.zip" -DestinationPath "$env:ChocolateyInstall\lib\$PackageName" -Force
  Remove-Item "$env:ChocolateyInstall\lib\$PackageName\_rels" -Recurse
  Remove-Item "$env:ChocolateyInstall\lib\$PackageName\package" -Recurse
  Remove-Item "$env:ChocolateyInstall\lib\$PackageName\[Content_Types].xml"
  New-Item -Path "${PSScriptRoot}\..\tmp\chocolatey\$PackageName" -ItemType "directory" -ErrorAction:SilentlyContinue
  choco pack "$env:ChocolateyInstall\lib\$PackageName\$PackageName.nuspec" --outdir "${PSScriptRoot}\..\tmp\chocolatey\$PackageName"
}

# Check for existence of required environment variables
if ( $null -eq $env:ChocolateyInstall ) {
  [Console]::Error.WriteLine('Missing $env:ChocolateyInstall environment variable')
  exit 1
}

# Add the cached packages with source priority 1 (Chocolatey community is 0)
New-Item -Path "${PSScriptRoot}\..\tmp\chocolatey" -ItemType "directory" -ErrorAction:SilentlyContinue
choco source add --name="cache" --source="${PSScriptRoot}\..\tmp\chocolatey" --priority=1

# Install nodejs v20.5.1 (will use cache if exists)
$nodejs = "nodejs"
choco install "$nodejs" --version="20.5.1" --require-checksums -y
# Internalise nodejs to cache if doesn't exist
if ( -not (Test-Path -Path "${PSScriptRoot}\..\tmp\chocolatey\$nodejs\$nodejs.20.5.1.nupkg" -PathType Leaf) ) {
  Save-ChocoPackage -PackageName $nodejs
}

# Install python v3.9.12 (will use cache if exists)
$python = "python3"
choco install $python --version="3.9.12" --require-checksums -y
# Internalise python to cache if doesn't exist
if ( -not (Test-Path -Path "${PSScriptRoot}\..\tmp\chocolatey\$python\$python.3.9.12.nupkg" -PathType Leaf) ) {
  Save-ChocoPackage -PackageName $python
}
