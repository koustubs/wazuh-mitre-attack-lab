#!/usr/bin/env bash
# Fetches the Wazuh manager package that prepare-engine-check.sh installs inside WSL so the real
# analysisd engine can evaluate lab_rules.xml offline.
#
# The package is half a gigabyte, so it is cached rather than committed. A clean clone has no
# .cache at all and the rule suite cannot run until this has been fetched once.
#
# The expected hash is the one published for 4.14.7-1 in the signed apt index at
# packages.wazuh.com, and it is the same value pinned in prepare-engine-check.sh. Anything that
# does not match is deleted rather than kept, because a rule suite running against an unverified
# engine proves nothing.
#
# Run as: wsl -d Ubuntu --exec bash tests/fetch-engine-package.sh
set -euo pipefail

project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
name=wazuh-manager_4.14.7-1_amd64.deb
url=https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-manager/$name
expected=1edd93f49ea1d89edcb7c17eeec750e99f685bc9f88d3c71f7972267c9442de0
target=$project/.cache/$name

command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required.' >&2; exit 1; }

if [[ -f $target ]] && [[ $(sha256sum "$target" | cut -d' ' -f1) == "$expected" ]]; then
    echo "Already cached and verified: $target"
    exit 0
fi

mkdir -p "$project/.cache"
# Download beside the target, not onto it. An interrupted transfer must never leave something
# that looks like a cached package.
part=$target.part
rm -f -- "$part"
echo "Fetching $name (about 508 MB)..."
curl --fail --location --proto '=https' --tlsv1.2 --progress-bar -o "$part" "$url"

actual=$(sha256sum "$part" | cut -d' ' -f1)
if [[ $actual != "$expected" ]]; then
    rm -f -- "$part"
    echo 'Downloaded package does not match the expected hash. It has been deleted.' >&2
    echo "  expected $expected" >&2
    echo "  actual   $actual" >&2
    exit 1
fi

mv -- "$part" "$target"
echo "Verified and cached: $target"
echo 'Next: wsl -d Ubuntu -u root --exec bash tests/prepare-engine-check.sh'
