// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.HashSet;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.WildcardTypePermission;

import org.junit.jupiter.api.Test;

/**
 * Guards the XStream whitelist contract the plugin relies on. {@code Role} is
 * returned over REST, so it must (a) live in the package the {@code allowTypes}
 * wildcard covers, and (b) survive a serialize/deserialize round-trip once that
 * wildcard is registered — otherwise every REST call returning a role throws
 * {@code ForbiddenClassException}.
 *
 * <p>The round-trip uses a plain {@link XStream} with the same wildcard the plugin
 * registers (rather than the engine's {@code ObjectXMLSerializer}, which needs
 * engine static init unavailable in a unit test) and a JDK-only {@link DomDriver}.</p>
 */
class RoleSerializationTest {

    private static final String WILDCARD = "com.diridium.rbac.**";

    @Test
    void roleIsCoveredByTheAllowTypesWildcard() {
        // The plugin registers allowTypes(Role.class.getPackage().getName() + ".**").
        // A package rename that moved Role out of com.diridium.rbac would silently drop
        // it from the whitelist; pin the invariant.
        assertEquals(WILDCARD, Role.class.getPackage().getName() + ".**");
    }

    @Test
    void roleSurvivesXStreamRoundTripUnderTheWildcard() {
        XStream xstream = new XStream(new DomDriver());
        xstream.addPermission(new WildcardTypePermission(new String[] { WILDCARD }));

        Role original = new Role();
        original.setId(42);
        original.setName("Auditor");
        original.setDescription("Read-only with channel limits");
        original.setPermissions(new HashSet<>(Arrays.asList("viewChannels", "viewMessages")));
        original.setChannelIds(new HashSet<>(Arrays.asList("ch-a", "ch-b")));
        original.setAdmin(true);

        String xml = xstream.toXML(original);
        Role restored = (Role) xstream.fromXML(xml);

        // Role has no equals(), so compare field-by-field.
        assertEquals(original.getId(), restored.getId());
        assertEquals(original.getName(), restored.getName());
        assertEquals(original.getDescription(), restored.getDescription());
        assertEquals(original.isAdmin(), restored.isAdmin());
        assertEquals(original.getPermissions(), restored.getPermissions());
        assertEquals(original.getChannelIds(), restored.getChannelIds());
    }
}
