#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_REMOTE="upstream"
UPSTREAM_BRANCH="master"
FEATURE_BRANCH="feature/openid-keycloak-sso"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}==> $*${NC}"; }
warn()  { echo -e "${YELLOW}==> $*${NC}"; }
error() { echo -e "${RED}==> $*${NC}" >&2; exit 1; }

# Ensure clean working tree
if ! git diff --quiet || ! git diff --cached --quiet; then
    error "Working tree is not clean. Commit or stash your changes first."
fi

ORIGINAL_BRANCH=$(git branch --show-current)

info "Fetching upstream..."
git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH"

LOCAL_MASTER=$(git rev-parse "$UPSTREAM_BRANCH")
REMOTE_MASTER=$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")

if [ "$LOCAL_MASTER" = "$REMOTE_MASTER" ]; then
    info "master is already up to date."
else
    NEW_COMMITS=$(git log --oneline "$LOCAL_MASTER".."$REMOTE_MASTER" | wc -l | tr -d ' ')
    info "Updating master ($NEW_COMMITS new commits)..."
    git checkout "$UPSTREAM_BRANCH"
    git merge --ff-only "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
fi

info "Rebasing $FEATURE_BRANCH onto $UPSTREAM_BRANCH..."
git checkout "$FEATURE_BRANCH"
git rebase "$UPSTREAM_BRANCH"

CUSTOM_COMMITS=$(git log --oneline "$UPSTREAM_BRANCH".."$FEATURE_BRANCH")
info "Feature branch has these custom commits:"
echo "$CUSTOM_COMMITS"

read -rp "Push with --force-with-lease to origin? [y/N] " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    git push --force-with-lease origin "$FEATURE_BRANCH"
    info "Pushed!"
else
    warn "Skipped push. You can push manually with:"
    echo "  git push --force-with-lease origin $FEATURE_BRANCH"
fi

# Return to original branch if different
if [ "$ORIGINAL_BRANCH" != "$FEATURE_BRANCH" ]; then
    git checkout "$ORIGINAL_BRANCH"
fi

info "Done!"
