#!/bin/bash
# Copyright (c) 2026 Maksym Bardakh. All rights reserved.
# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Source-available under LICENSE.md with the permissions in LICENSING.md.
#
# Pair a connected DeskID token to this macOS account, or undo it.
#
#   tools/sc_auth_gate.sh status     # read-only: what is paired, what could break
#   tools/sc_auth_gate.sh pair       # preflight, pair, verify (needs an admin password)
#   tools/sc_auth_gate.sh unpair     # undo, no admin password needed
#
# Pairing rewrites how this account authenticates, so `pair` refuses to run
# until the preflight passes and unwinds itself if any step after the pairing
# fails. The escape hatches, in order of how fast they work: unplug the token,
# run `sc_auth unpair`, or authenticate at the FileVault preboot screen, which
# never uses the card.

set -u

readonly USER_NAME="${SUDO_USER:-$(id -un)}"

fail() {
    echo "error: $*" >&2
    exit 1
}

identity_hash() {
    sc_auth identities 2>/dev/null | awk '/^[0-9A-F]{40}\t/ {print $1; exit}'
}

show_status() {
    echo "account            $USER_NAME"
    echo "admin accounts     $(dscl . -read /Groups/admin GroupMembership 2>/dev/null |
                               cut -d' ' -f2- | tr -s ' ')"
    echo "filevault          $(fdesetup status 2>/dev/null | head -1)"
    echo "filevault by card  $(sc_auth filevault -o status 2>&1 | head -1)"
    echo "pairing dialog     $(sc_auth pairing_ui -s status 2>&1 | head -1)"
    echo
    echo "identities on the inserted card:"
    sc_auth identities 2>&1 | sed 's/^/  /'
    echo
    local paired
    paired="$(sc_auth list -u "$USER_NAME" 2>&1)"
    echo "hashes that can authenticate $USER_NAME:"
    echo "  ${paired:-(none)}"
}

preflight() {
    local hash admins
    hash="$(identity_hash)"
    [ -n "$hash" ] || fail "no card identity found — connect the token and check \`sc_auth identities\`"

    admins="$(dscl . -read /Groups/admin GroupMembership 2>/dev/null |
              cut -d' ' -f2- | tr ' ' '\n' | grep -cvE '^(root|_.*)?$')"
    if [ "$admins" -lt 2 ]; then
        echo "warning: $USER_NAME is the only human administrator on this Mac." >&2
        echo "         Recovery still works — FileVault preboot authenticates with your" >&2
        echo "         password, and unplugging the token restores password login — but" >&2
        echo "         creating a second admin account first costs nothing." >&2
        echo >&2
    fi
    echo "$hash"
}

case "${1:-status}" in
status)
    show_status
    ;;

pair)
    hash="$(preflight)" || exit 1
    echo "pairing $hash to $USER_NAME"
    echo "undo at any time with:  sc_auth unpair -u $USER_NAME -h $hash"
    echo
    sudo sc_auth pair -u "$USER_NAME" -h "$hash" || fail "pairing failed, nothing changed"

    trap 'echo; echo "unwinding — unpairing $hash"; sc_auth unpair -u "$USER_NAME" -h "$hash"' ERR
    sc_auth list -u "$USER_NAME" | grep -qi "$hash" ||
        fail "pairing reported success but \`sc_auth list\` does not show the hash"
    trap - ERR

    echo
    echo "paired. What to look at next, in increasing order of commitment:"
    echo "  1. sudo -k && sudo true          expect a PIN prompt, not a password prompt"
    echo "  2. lock the screen (ctrl-cmd-q)  expect a PIN field with the token inserted"
    echo "  3. log out and back in           the real E1a answer"
    echo
    echo "DeskID accepts any 6-8 digit PIN once the fingerprint gate is satisfied, so"
    echo "type anything at the prompt. Unplugging the token restores password entry."
    echo
    echo "when finished:  tools/sc_auth_gate.sh unpair"
    ;;

unpair)
    sc_auth unpair -u "$USER_NAME" || fail "unpair failed — try \`sudo sc_auth unpair -u $USER_NAME\`"
    echo "unpaired. Remaining hashes for $USER_NAME:"
    echo "  $(sc_auth list -u "$USER_NAME" 2>&1)"
    ;;

*)
    sed -n '3,15p' "$0" | cut -c3-
    exit 1
    ;;
esac
