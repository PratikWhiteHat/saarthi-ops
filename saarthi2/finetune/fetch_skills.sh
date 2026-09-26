#!/usr/bin/env bash
# Download the Claude-BugHunter skill corpus into ./skills (reproducible).
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

URL="https://github.com/elementalsouls/Claude-BugHunter/archive/refs/heads/main.tar.gz"
echo "Downloading skills from ${URL} …"
curl -fsSL --max-time 180 "$URL" -o repo.tar.gz
rm -rf skills
tar xzf repo.tar.gz --strip-components=1 'Claude-BugHunter-main/skills'
rm -f repo.tar.gz
echo "Fetched $(find skills -name SKILL.md | wc -l | tr -d ' ') skills into ./skills"
