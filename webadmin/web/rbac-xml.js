// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

function escapeXml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

export function generateRolesXml(roles, includeChannels = true) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<com.diridium.rbac.RbacSettingsPanel_-RoleExportContainer>\n';
    xml += '  <roles>\n';
    roles.forEach((r) => {
        xml += `    <com.diridium.rbac.Role>\n`;
        xml += `      <id>${escapeXml(r.id || 1)}</id>\n`;
        xml += `      <name>${escapeXml(r.name)}</name>\n`;
        xml += `      <description>${escapeXml(r.description || '')}</description>\n`;

        xml += `      <permissions>\n`;
        const perms = r.permissions;
        if (perms) {
            let permList = [];
            if (Array.isArray(perms)) {
                permList = perms;
            } else if (perms instanceof Set) {
                permList = Array.from(perms);
            } else if (typeof perms === 'object') {
                permList = Object.entries(perms)
                    .filter(([k, v]) => v === true || v === 'true' || typeof v !== 'boolean')
                    .map(([k]) => k);
            }
            permList.forEach((p) => {
                xml += `        <string>${escapeXml(p)}</string>\n`;
            });
        }
        xml += `      </permissions>\n`;

        const channels = r.channelIds || r.channels;
        if (includeChannels && channels && ((Array.isArray(channels) && channels.length > 0) || (channels instanceof Set && channels.size > 0))) {
            xml += `      <channelIds>\n`;
            const chList = Array.isArray(channels) ? channels : (channels instanceof Set ? Array.from(channels) : Object.keys(channels));
            chList.forEach((c) => {
                xml += `        <string>${escapeXml(c)}</string>\n`;
            });
            xml += `      </channelIds>\n`;
        } else {
            xml += `      <channelIds/>\n`;
        }

        xml += `      <isAdmin>${r.isAdmin ? 'true' : 'false'}</isAdmin>\n`;
        xml += `    </com.diridium.rbac.Role>\n`;
    });
    xml += '  </roles>\n';
    xml += '</com.diridium.rbac.RbacSettingsPanel_-RoleExportContainer>';
    return xml;
}

export function parseRolesXml(text) {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(text, 'text/xml');

    if (xmlDoc.querySelector('parsererror')) {
        throw new Error('Invalid XML format.');
    }

    let roleNodes = xmlDoc.getElementsByTagName('com.diridium.rbac.Role');
    if (roleNodes.length === 0) {
        roleNodes = xmlDoc.getElementsByTagName('role');
    }
    if (roleNodes.length === 0) {
        throw new Error('No roles found in XML.');
    }

    const importedList = [];
    for (let i = 0; i < roleNodes.length; i++) {
        const rNode = roleNodes[i];
        const nameNode = rNode.getElementsByTagName('name')[0];
        const descNode = rNode.getElementsByTagName('description')[0];

        const permContainer = rNode.getElementsByTagName('permissions')[0];
        const permNodes = permContainer ? permContainer.getElementsByTagName('string') : rNode.getElementsByTagName('permission');

        const channelContainer = rNode.getElementsByTagName('channelIds')[0] || rNode.getElementsByTagName('channels')[0];
        const channelNodes = channelContainer ? channelContainer.getElementsByTagName('string') : rNode.getElementsByTagName('channel');

        if (!nameNode) continue;
        const name = nameNode.textContent.trim();
        const description = descNode ? descNode.textContent.trim() : '';

        const permissions = new Set();
        for (let j = 0; j < permNodes.length; j++) {
            permissions.add(permNodes[j].textContent.trim());
        }

        const channelIds = new Set();
        for (let j = 0; j < channelNodes.length; j++) {
            channelIds.add(channelNodes[j].textContent.trim());
        }

        importedList.push({ name, description, permissions, channelIds });
    }

    return importedList;
}