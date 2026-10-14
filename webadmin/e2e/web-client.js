// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

// The web client release CI tests against: OIE_WEB_CLIENT_REF in
// .github/workflows/build.yml. Unset locally, where every test runs against
// whatever checkout WEBADMIN_DIR points at.
const pinned = /^v(\d+)\.(\d+)\./.exec(process.env.OIE_WEB_CLIENT_REF ?? '');

/** True when CI pins a web client release older than major.minor. */
export function webClientOlderThan(major, minor) {
    if (!pinned) return false;
    const [pinnedMajor, pinnedMinor] = [Number(pinned[1]), Number(pinned[2])];
    return pinnedMajor < major || (pinnedMajor === major && pinnedMinor < minor);
}
