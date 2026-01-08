#!/bin/bash

# Release Management Script for ethr
# Usage: 
#   ./release.sh                      # Interactive mode
#   ./release.sh <version>            # Create release (non-interactive)
#   ./release.sh <version> --latest   # Create release and set as latest
#   ./release.sh --set-latest [version] # Only update latest tag
#   ./release.sh --list               # List versions and exit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to show existing tags
show_existing_versions() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        Existing Versions               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    
    if git tag -l "v*" | grep -q .; then
        git tag -l "v*" --sort=-version:refname | head -20 | while read tag; do
            echo "  $tag"
        done
        local tag_count=$(git tag -l "v*" | wc -l)
        if [ "$tag_count" -gt 20 ]; then
            echo -e "${CYAN}  ... (showing 20 of $tag_count versions)${NC}"
        fi
    else
        echo -e "${YELLOW}  No existing versions found${NC}"
    fi
    echo ""
}

# Function to show current latest
show_current_latest() {
    if git rev-parse latest >/dev/null 2>&1; then
        local latest_commit=$(git rev-parse latest)
        local latest_tag=$(git tag --points-at "$latest_commit" | grep "^v" | head -1)
        echo -e "${CYAN}Current 'latest' tag:${NC}"
        if [ -n "$latest_tag" ]; then
            echo -e "  → ${GREEN}$latest_tag${NC}"
        else
            echo -e "  → ${YELLOW}${latest_commit:0:8} (no version tag)${NC}"
        fi
    else
        echo -e "${YELLOW}No 'latest' tag exists yet${NC}"
    fi
    echo ""
}

# Function to update latest tag
update_latest_tag() {
    local target_version=$1
    
    # Add 'v' prefix if not present
    if [[ ! "$target_version" =~ ^v ]]; then
        target_version="v${target_version}"
    fi
    
    # Check if the target version exists
    if ! git rev-parse "$target_version" >/dev/null 2>&1; then
        echo -e "${RED}Error: Tag ${target_version} does not exist${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Updating 'latest' tag to ${target_version}...${NC}"
    
    # Delete the 'latest' tag locally and remotely if it exists
    git tag -d latest 2>/dev/null || true
    git push origin :refs/tags/latest 2>/dev/null || true
    
    # Create new 'latest' tag pointing to the target version
    git tag latest "$target_version"
    git push origin latest
    
    echo ""
    echo -e "${GREEN}✓ 'latest' tag now points to ${target_version}${NC}"
    echo ""
    echo "Users can now download this version using:"
    echo "  https://github.com/$(git remote get-url origin | sed -E 's|.*github.com[:/]||' | sed 's|.git$||')/releases/latest"
}

# Function to update latest release (tag + GitHub release with binaries)
update_latest_release() {
    local target_version=$1
    
    # Add 'v' prefix if not present
    if [[ ! "$target_version" =~ ^v ]]; then
        target_version="v${target_version}"
    fi
    
    # Check if gh CLI is available
    if ! command -v gh &> /dev/null; then
        echo -e "${RED}Error: GitHub CLI (gh) is not installed${NC}"
        echo "Install it from: https://cli.github.com/"
        echo ""
        echo "Alternatively, you can update the latest release via GitHub Actions:"
        echo "  1. Go to your repo → Actions → 'Set Latest Release'"
        echo "  2. Click 'Run workflow' and enter version: ${target_version}"
        return 1
    fi
    
    # Check if logged in to gh
    if ! gh auth status &> /dev/null; then
        echo -e "${RED}Error: Not logged in to GitHub CLI${NC}"
        echo "Run: gh auth login"
        return 1
    fi
    
    # Check if the target version tag exists
    if ! git rev-parse "$target_version" >/dev/null 2>&1; then
        echo -e "${RED}Error: Tag ${target_version} does not exist${NC}"
        return 1
    fi
    
    # Check if a release exists for this tag
    if ! gh release view "$target_version" &> /dev/null; then
        echo -e "${RED}Error: No GitHub release found for ${target_version}${NC}"
        echo "The release may not have been created yet, or the build may have failed."
        return 1
    fi
    
    echo -e "${GREEN}Updating 'latest' release to ${target_version}...${NC}"
    echo ""
    
    # Create temp directory for assets
    local tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT
    
    # Download assets from target release
    echo "Downloading release assets from ${target_version}..."
    if ! gh release download "$target_version" --dir "$tmp_dir" 2>/dev/null; then
        echo -e "${YELLOW}Warning: Could not download assets (release may have no files yet)${NC}"
    fi
    
    # Update git tag first
    echo "Updating git tag..."
    git tag -d latest 2>/dev/null || true
    git push origin :refs/tags/latest 2>/dev/null || true
    git tag latest "$target_version"
    git push origin latest
    
    # Delete existing 'latest' release if it exists
    echo "Removing existing 'latest' release..."
    gh release delete latest --yes 2>/dev/null || true
    
    # Get the commit SHA for the version tag
    local target_sha=$(git rev-parse "${target_version}^{}")
    
    # Create new 'latest' release
    echo "Creating new 'latest' release..."
    local asset_args=""
    if [ -n "$(ls -A $tmp_dir 2>/dev/null)" ]; then
        asset_args="$tmp_dir/*"
    fi
    
    if [ -n "$asset_args" ]; then
        gh release create latest \
            --title "Latest Release ($target_version)" \
            --notes "This release always points to the latest stable version.

**Current Version:** $target_version

See the [versioned release](https://github.com/$(git remote get-url origin | sed -E 's|.*github.com[:/]||' | sed 's|.git$||')/releases/tag/$target_version) for full release notes.

---
*Updated via release.sh on $(date -u '+%Y-%m-%d %H:%M UTC')*" \
            --target "$target_sha" \
            $tmp_dir/*
    else
        gh release create latest \
            --title "Latest Release ($target_version)" \
            --notes "This release always points to the latest stable version.

**Current Version:** $target_version

See the [versioned release](https://github.com/$(git remote get-url origin | sed -E 's|.*github.com[:/]||' | sed 's|.git$||')/releases/tag/$target_version) for full release notes.

---
*Updated via release.sh on $(date -u '+%Y-%m-%d %H:%M UTC')*" \
            --target "$target_sha"
    fi
    
    echo ""
    echo -e "${GREEN}✓ 'latest' release now points to ${target_version}${NC}"
    echo ""
    echo "Users can now download this version using:"
    echo "  https://github.com/$(git remote get-url origin | sed -E 's|.*github.com[:/]||' | sed 's|.git$||')/releases/latest"
}

# Interactive mode
interactive_mode() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Ethr Release Management Tool        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    show_existing_versions
    show_current_latest
    
    echo -e "${YELLOW}What would you like to do?${NC}"
    echo ""
    echo "  1) Create a new release"
    echo "  2) Update the 'latest' tag"
    echo "  3) List versions and exit"
    echo "  4) Exit"
    echo ""
    read -p "Choose an option (1-4): " choice
    
    case $choice in
        1)
            echo ""
            echo -e "${YELLOW}Enter the version number for the new release${NC}"
            echo "Format: MAJOR.MINOR.PATCH (e.g., 1.0.0, 2.1.3)"
            echo "Or with pre-release: 2.0.0-alpha.1, 2.0.0-beta.2, 2.0.0-rc.1"
            echo ""
            read -p "Version: " VERSION
            
            if [ -z "$VERSION" ]; then
                echo -e "${RED}Error: Version cannot be empty${NC}"
                exit 1
            fi
            
            echo ""
            read -p "Set this as 'latest' tag? (y/N): " set_latest
            if [[ $set_latest =~ ^[Yy]$ ]]; then
                SET_LATEST=true
            else
                SET_LATEST=false
            fi
            
            create_release "$VERSION" "$SET_LATEST"
            ;;
        2)
            echo ""
            show_existing_versions
            echo -e "${YELLOW}Enter the version to set as 'latest'${NC}"
            read -p "Version: " TARGET_VERSION
            
            if [ -z "$TARGET_VERSION" ]; then
                echo -e "${RED}Error: Version cannot be empty${NC}"
                exit 1
            fi
            
            update_latest_release "$TARGET_VERSION"
            ;;
        3)
            exit 0
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            exit 1
            ;;
    esac
}

# Function to create release
create_release() {
    local VERSION=$1
    local SET_LATEST=$2
    local TAG="v${VERSION}"
    
    echo ""
    echo -e "${YELLOW}Creating release ${TAG}...${NC}"
    echo ""

    # Check if we're on the right branch
    CURRENT_BRANCH=$(git branch --show-current)
    if [ "$CURRENT_BRANCH" != "master" ] && [ "$CURRENT_BRANCH" != "main" ]; then
        echo -e "${YELLOW}Warning: You're on branch '${CURRENT_BRANCH}', not 'master' or 'main'${NC}"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        echo -e "${RED}Error: You have uncommitted changes${NC}"
        echo "Please commit or stash your changes before creating a release"
        exit 1
    fi

    # Check if tag already exists
    if git rev-parse "$TAG" >/dev/null 2>&1; then
        echo -e "${RED}Error: Tag ${TAG} already exists${NC}"
        echo "If you want to replace it, run:"
        echo "  git tag -d ${TAG}"
        echo "  git push origin :refs/tags/${TAG}"
        exit 1
    fi

    # Confirm release
    echo -e "${YELLOW}This will:${NC}"
    echo "  1. Create and push tag: ${TAG}"
    echo "  2. Trigger GitHub Actions to build for all platforms"
    echo "  3. Create a GitHub Release with binaries"
    if [ "$SET_LATEST" = true ]; then
        echo "  4. Update the 'latest' tag to point to ${TAG}"
    else
        echo "  4. The 'latest' tag will NOT be updated"
    fi
    echo ""
    read -p "Proceed with release? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Release cancelled"
        exit 0
    fi

    # Create and push tag
    echo ""
    echo -e "${GREEN}Creating tag ${TAG}...${NC}"
    git tag -a "$TAG" -m "Release ${TAG}"

    echo -e "${GREEN}Pushing tag to GitHub...${NC}"
    git push origin "$TAG"

    # Update latest tag if requested
    if [ "$SET_LATEST" = true ]; then
        echo ""
        update_latest_tag "$TAG"
    fi

    echo ""
    echo -e "${GREEN}✓ Release initiated!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Watch the build progress:"
    echo "     https://github.com/$(git remote get-url origin | sed -E 's|.*github.com[:/]||' | sed 's|.git$||')/actions"
    echo ""
    echo "  2. Once complete, check the release:"
    echo "     https://github.com/$(git remote get-url origin | sed -E 's|.*github.com[:/]||' | sed 's|.git$||')/releases/tag/${TAG}"
    echo ""
    if [ "$SET_LATEST" = false ]; then
        echo "  3. To set as latest later, run:"
        echo "     ./release.sh --set-latest ${TAG#v}"
        echo ""
    fi
}

# Parse arguments
MODE=""
VERSION=""
SET_LATEST=false

for arg in "$@"; do
    case $arg in
        --help|-h)
            echo "Ethr Release Management Tool"
            echo ""
            echo "Usage:"
            echo "  $0                           # Interactive mode (default)"
            echo "  $0 <version>                 # Create release"
            echo "  $0 <version> --latest        # Create release and set as latest"
            echo "  $0 --set-latest [version]    # Update latest tag only"
            echo "  $0 --list                    # List versions and exit"
            echo ""
            echo "Examples:"
            echo "  $0                           # Interactive menu"
            echo "  $0 1.0.0                     # Create v1.0.0 release"
            echo "  $0 1.0.0 --latest            # Create v1.0.0 and set as latest"
            echo "  $0 --set-latest 1.0.0        # Set v1.0.0 as latest"
            echo "  $0 --list                    # Show all versions"
            echo ""
            exit 0
            ;;
        --list)
            show_existing_versions
            show_current_latest
            exit 0
            ;;
        --set-latest)
            MODE="set-latest"
            ;;
        --latest)
            SET_LATEST=true
            ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION=$arg
            fi
            ;;
    esac
done

# Handle different modes
if [ "$MODE" = "set-latest" ]; then
    # Set latest mode
    if [ -z "$VERSION" ]; then
        show_existing_versions
        echo -e "${YELLOW}Enter the version to set as 'latest'${NC}"
        read -p "Version: " VERSION
        
        if [ -z "$VERSION" ]; then
            echo -e "${RED}Error: Version cannot be empty${NC}"
            exit 1
        fi
    fi
    
    update_latest_release "$VERSION"
    
elif [ -z "$VERSION" ]; then
    # No version provided - interactive mode
    interactive_mode
    
else
    # Version provided - create release
    create_release "$VERSION" "$SET_LATEST"
fi
