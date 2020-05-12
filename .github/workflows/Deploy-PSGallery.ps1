Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

try{
    Publish-Module -Path "$env:GITHUB_WORKSPACE\PSVesmir" -NuGetApiKey "$env:POWERSHELL_GALLERY_API_KEY" -ErrorAction Stop -Force -Debug
    Write-Host "Cool, we done here."
}
catch { 
    throw $_ 
}