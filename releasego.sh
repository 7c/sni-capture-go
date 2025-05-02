#!/bin/bash
set -e

# Check if an argument was provided
if [ $# -eq 0 ]; then
    echo -e "\033[31mError: Please provide a release message\033[0m"
    echo "Usage: $0 \"Your release message\""
    exit 1
fi

RELEASE_MESSAGE="$*"
VERSION_FILE="./version.txt"

# Validate semver function
validate_semver() {
    local version=$1
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "\033[31mError: Version $version is not a valid semver (X.Y.Z format required)\033[0m"
        exit 1
    fi
}

# Initialize version file if it doesn't exist
if [ ! -f "$VERSION_FILE" ]; then
    echo "0.0.1" > "$VERSION_FILE"
    echo -e "\033[33mInitialized version file with 0.0.1\033[0m"
fi

# Read and validate current version
CURRENT_VERSION=$(cat "$VERSION_FILE")
validate_semver "$CURRENT_VERSION"

# Check git status
GIT_STATUS=$(git status --porcelain)
if [ ! -z "$GIT_STATUS" ]; then
    echo -e "\033[31mError: You have uncommitted changes:\033[0m"
    git status
    exit 1
fi

# Check if current HEAD is already tagged
if git describe --exact-match --tags HEAD >/dev/null 2>&1; then
    echo -e "\033[31mError: Current commit is already tagged with $(git describe --exact-match --tags HEAD)\033[0m"
else 
    # Tag the commit
    TAG_NAME="v${CURRENT_VERSION}"
    echo -e "\033[32mTagging commit with ${TAG_NAME}\033[0m"
    git tag -a "${TAG_NAME}" -m "${RELEASE_MESSAGE}"

    echo -e "\033[32mSuccessfully created tag ${TAG_NAME}\033[0m"
fi

# determine current branch
BRANCH=$(git branch --show-current)

# Push the tag to the remote repository
echo -e "\033[32mPushing tag ${TAG_NAME} to remote repository\033[0m"
git push origin "${BRANCH}"
git push --tags
echo -e "\033[32mSuccessfully pushed tag ${TAG_NAME} to remote repository\033[0m"

## increase the version number
# read the current version
CURRENT_VERSION=$(cat "$VERSION_FILE")

NEW_VERSION=$(awk -vFS=. -vOFS=. '{$NF++;print}' <<< "$CURRENT_VERSION")

# write the new version to the version file
echo "$NEW_VERSION" > "$VERSION_FILE"