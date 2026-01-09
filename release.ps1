<#
.SYNOPSIS
    Release Management Script for ethr (Windows PowerShell version)

.DESCRIPTION
    Creates releases, manages tags, and updates the latest release on GitHub.

.PARAMETER Version
    The version number to release (e.g., 1.0.0)

.PARAMETER Latest
    Set this release as the latest release

.PARAMETER SetLatest
    Update the latest release to point to an existing version

.PARAMETER List
    List existing versions and exit

.EXAMPLE
    .\release.ps1                      # Interactive mode
    .\release.ps1 -Version 1.0.0       # Create release
    .\release.ps1 -Version 1.0.0 -Latest  # Create release and set as latest
    .\release.ps1 -SetLatest 1.0.0     # Update latest to point to v1.0.0
    .\release.ps1 -List                # List versions
#>

param(
    [string]$Version,
    [switch]$Latest,
    [string]$SetLatest,
    [switch]$List,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Info { param($msg) Write-Host $msg -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host $msg -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host $msg -ForegroundColor Red }

# Get GitHub repo from git remote
function Get-GitHubRepo {
    $remote = git remote get-url origin 2>$null
    if ($remote -match "github\.com[:/](.+?)(?:\.git)?$") {
        return $matches[1]
    }
    return $null
}

$script:GitHubRepo = Get-GitHubRepo

function Show-ExistingVersions {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "        Existing Versions               " -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
    
    $tags = git tag -l "v*" --sort=-version:refname 2>$null | Select-Object -First 20
    if ($tags) {
        foreach ($tag in $tags) {
            Write-Host "  $tag"
        }
        $totalTags = (git tag -l "v*" | Measure-Object).Count
        if ($totalTags -gt 20) {
            Write-Info "  ... (showing 20 of $totalTags versions)"
        }
    } else {
        Write-Warn "  No existing versions found"
    }
    Write-Host ""
}

function Show-CurrentLatest {
    try {
        $latestCommit = git rev-parse latest 2>$null
        if ($LASTEXITCODE -eq 0 -and $latestCommit) {
            $latestTag = git tag --points-at $latestCommit 2>$null | Where-Object { $_ -match "^v" } | Select-Object -First 1
            Write-Info "Current latest tag:"
            if ($latestTag) {
                Write-Success "  -> $latestTag"
            } else {
                Write-Warn "  -> $($latestCommit.Substring(0,8)) (no version tag)"
            }
        } else {
            Write-Warn "No latest tag exists yet"
        }
    } catch {
        Write-Warn "No latest tag exists yet"
    }
    Write-Host ""
}

function Update-LatestTag {
    param([string]$TargetVersion)
    
    if (-not $TargetVersion.StartsWith("v")) {
        $TargetVersion = "v$TargetVersion"
    }
    
    $tagExists = git rev-parse $TargetVersion 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: Tag $TargetVersion does not exist"
        return $false
    }
    
    Write-Success "Updating latest tag to $TargetVersion..."
    
    # These may fail if tag doesn't exist - that's OK
    $ErrorActionPreference = "SilentlyContinue"
    git tag -d latest 2>&1 | Out-Null
    git push origin :refs/tags/latest 2>&1 | Out-Null
    $ErrorActionPreference = "Stop"
    
    git tag latest $TargetVersion
    git push origin latest 2>&1 | Out-Null
    
    Write-Host ""
    Write-Success "[OK] latest tag now points to $TargetVersion"
    return $true
}

function Update-LatestRelease {
    param([string]$TargetVersion)
    
    if (-not $TargetVersion.StartsWith("v")) {
        $TargetVersion = "v$TargetVersion"
    }
    
    # Check gh CLI
    $ghCmd = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $ghCmd) {
        Write-Err "Error: GitHub CLI (gh) is not installed"
        Write-Host "Install it from: https://cli.github.com/"
        Write-Host ""
        Write-Host "Alternatively, use GitHub Actions:"
        Write-Host "  1. Go to repo -> Actions -> Set Latest Release"
        Write-Host "  2. Click Run workflow and enter version: $TargetVersion"
        return $false
    }
    
    # Check auth
    gh auth status 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: Not logged in to GitHub CLI"
        Write-Host "Run: gh auth login"
        return $false
    }
    
    # Check tag exists
    git rev-parse $TargetVersion 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: Tag $TargetVersion does not exist"
        return $false
    }
    
    # Check release exists
    gh release view $TargetVersion --repo $script:GitHubRepo 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: No GitHub release found for $TargetVersion"
        Write-Host "The release may not have been created yet, or the build may have failed."
        return $false
    }
    
    Write-Success "Setting $TargetVersion as the latest release..."
    Write-Host ""
    
    # Update git 'latest' tag to point to this version
    Write-Host "Updating git latest tag..."
    $ErrorActionPreference = "SilentlyContinue"
    git tag -d latest 2>&1 | Out-Null
    git push origin :refs/tags/latest 2>&1 | Out-Null
    git tag latest $TargetVersion
    git push origin latest 2>&1 | Out-Null
    $ErrorActionPreference = "Stop"
    
    # Mark the release as "latest" using GitHub's built-in feature
    Write-Host "Marking GitHub release as latest..."
    gh release edit $TargetVersion --repo $script:GitHubRepo --latest
    
    Write-Host ""
    Write-Success "[OK] $TargetVersion is now the latest release"
    Write-Host ""
    Write-Host "Users can download from:"
    Write-Host "  https://github.com/$($script:GitHubRepo)/releases/latest"
    Write-Host "  (redirects to $TargetVersion)"
    
    return $true
}

function New-Release {
    param(
        [string]$ReleaseVersion,
        [bool]$SetAsLatest
    )
    
    $Tag = "v$ReleaseVersion"
    
    Write-Host ""
    Write-Warn "Creating release $Tag..."
    Write-Host ""
    
    # Check branch
    $currentBranch = git branch --show-current
    if ($currentBranch -ne "master" -and $currentBranch -ne "main") {
        Write-Warn "Warning: You are on branch $currentBranch, not master or main"
        $confirm = Read-Host "Continue anyway? (y/N)"
        if ($confirm -ne "y" -and $confirm -ne "Y") {
            return $false
        }
    }
    
    # Check for uncommitted changes
    git diff-index --quiet HEAD -- 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Error: You have uncommitted changes"
        Write-Host "Please commit or stash your changes before creating a release"
        return $false
    }
    
    # Check if tag exists
    git rev-parse $Tag 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Err "Error: Tag $Tag already exists"
        Write-Host "If you want to replace it, run:"
        Write-Host "  git tag -d $Tag"
        Write-Host "  git push origin :refs/tags/$Tag"
        return $false
    }
    
    # Confirm
    Write-Warn "This will:"
    Write-Host "  1. Create and push tag: $Tag"
    Write-Host "  2. Trigger GitHub Actions to build for all platforms"
    Write-Host "  3. Create a GitHub Release with binaries"
    if ($SetAsLatest) {
        Write-Host "  4. Update the latest tag to point to $Tag"
    } else {
        Write-Host "  4. The latest tag will NOT be updated"
    }
    Write-Host ""
    $confirm = Read-Host "Proceed with release? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Host "Release cancelled"
        return $false
    }
    
    # Create and push tag
    Write-Host ""
    Write-Success "Creating tag $Tag..."
    git tag -a $Tag -m "Release $Tag"
    
    Write-Success "Pushing tag to GitHub..."
    git push origin $Tag 2>&1 | Out-Null
    
    if ($SetAsLatest) {
        Write-Host ""
        Update-LatestTag -TargetVersion $Tag | Out-Null
    }
    
    Write-Host ""
    Write-Success "[OK] Release initiated!"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Watch the build progress:"
    Write-Host "     https://github.com/$($script:GitHubRepo)/actions"
    Write-Host ""
    Write-Host "  2. Once complete, check the release:"
    Write-Host "     https://github.com/$($script:GitHubRepo)/releases/tag/$Tag"
    Write-Host ""
    if (-not $SetAsLatest) {
        Write-Host "  3. To set as latest later, run:"
        Write-Host "     .\release.ps1 -SetLatest $ReleaseVersion"
        Write-Host ""
    }
    
    return $true
}

function Show-InteractiveMenu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "    Ethr Release Management Tool        " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Show-ExistingVersions
    Show-CurrentLatest
    
    Write-Warn "What would you like to do?"
    Write-Host ""
    Write-Host "  1) Create a new release"
    Write-Host "  2) Update the latest release"
    Write-Host "  3) List versions and exit"
    Write-Host "  4) Exit"
    Write-Host ""
    $choice = Read-Host "Choose an option (1-4)"
    
    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Warn "Enter the version number for the new release"
            Write-Host "Format: MAJOR.MINOR.PATCH (e.g., 1.0.0, 2.1.3)"
            Write-Host ""
            $ver = Read-Host "Version"
            
            if ([string]::IsNullOrWhiteSpace($ver)) {
                Write-Err "Error: Version cannot be empty"
                return
            }
            
            Write-Host ""
            $setLatest = Read-Host "Set this as latest release? (y/N)"
            $isLatest = $setLatest -eq "y" -or $setLatest -eq "Y"
            
            New-Release -ReleaseVersion $ver -SetAsLatest $isLatest
        }
        "2" {
            Write-Host ""
            Show-ExistingVersions
            Write-Warn "Enter the version to set as latest"
            $ver = Read-Host "Version"
            
            if ([string]::IsNullOrWhiteSpace($ver)) {
                Write-Err "Error: Version cannot be empty"
                return
            }
            
            Update-LatestRelease -TargetVersion $ver
        }
        "3" {
            return
        }
        "4" {
            Write-Host "Exiting..."
            return
        }
        default {
            Write-Err "Invalid option"
        }
    }
}

# Main
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

if ($List) {
    Show-ExistingVersions
    Show-CurrentLatest
    exit 0
}

if ($SetLatest) {
    $result = Update-LatestRelease -TargetVersion $SetLatest
    if ($result) { exit 0 } else { exit 1 }
}

if ($Version) {
    $result = New-Release -ReleaseVersion $Version -SetAsLatest $Latest.IsPresent
    if ($result) { exit 0 } else { exit 1 }
}

# No arguments - interactive mode
Show-InteractiveMenu
