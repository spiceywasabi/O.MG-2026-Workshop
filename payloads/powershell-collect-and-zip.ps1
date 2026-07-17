<#
.SYNOPSIS
Search for specific file extensions to collect and compress them.

.DESCRIPTION
Search for specific file extensions to collect all such files and compress them for further processing.

.LINK
https://github.com/0i41E
#>

# Define the file extension to search for
$fileType = "*.xzy"  # Change this to your desired file type (e.g., *.jpg, *.png, *.docx)

# Define the output ZIP file name
$outputZip = "C:\Users\Public\out.zip"  # Change this path as needed

# Ensure the output directory exists
$outputDir = [System.IO.Path]::GetDirectoryName($outputZip)
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}

# Initialize a temporary folder to store found files
$tempFolder = "$env:TEMP\FoundFiles"
if (Test-Path $tempFolder) {
    Remove-Item -Recurse -Force $tempFolder
}
New-Item -ItemType Directory -Path $tempFolder | Out-Null

# Search all drives for the specified file type
Write-Host -ForegroundColor Green "Searching for files of type '$fileType' on all drives..."
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $drive = $_.Root
    try {
        Get-ChildItem -Path $drive -Recurse -Filter $fileType -ErrorAction SilentlyContinue |
        ForEach-Object {
            $destination = Join-Path -Path $tempFolder -ChildPath $_.Name
            Copy-Item -Path $_.FullName -Destination $destination -Force
        }
    } catch {
        Write-Host "Failed to scan drive ${drive}: $_" -ForegroundColor Red
    }
}

# Compress the collected files into a ZIP archive
Write-Host -ForegroundColor Yellow "Compressing files into $outputZip..."
if (Test-Path $outputZip) {
    Remove-Item -Force $outputZip
}
Compress-Archive -Path "$tempFolder\*" -DestinationPath $outputZip

# Clean up the temporary folder
Write-Host -ForegroundColor Yellow "Cleaning up temporary files..."
Remove-Item -Recurse -Force $tempFolder

Write-Host "Operation completed. Files have been compressed into $outputZip" -ForegroundColor Green
