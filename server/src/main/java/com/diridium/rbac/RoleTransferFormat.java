// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Writes and reads role export files, format 1 ({@code docs/role-export-format.md}).
 *
 * <p>Reading is strict on purpose. A file is refused as a whole, with the reason,
 * if it is a format this code doesn't read, lacks a field format 1 requires, or
 * carries an element or attribute format 1 doesn't define. A later rbac may add to
 * the format, and refusing what this one doesn't understand is what stops it from
 * silently dropping that. The format version is checked before anything else, so
 * a newer file is reported as newer rather than as damaged.</p>
 *
 * <p>The parser refuses any DOCTYPE, which rules out external entities and entity
 * expansion. XStream isn't involved, so nothing in a file can name a Java type.</p>
 */
final class RoleTransferFormat {

    static final String FORMAT_VERSION = "1";

    /** Far more than any real export; bounds what the parser is asked to read. */
    static final int MAX_CHARS = 5 * 1024 * 1024;

    // The rbac_role and rbac_role_permission column sizes on every database.
    static final int MAX_NAME = 255;
    static final int MAX_PERMISSION = 255;
    static final int MAX_DESCRIPTION = 1024;

    /** A channel as written in the file: its id, and its name on the engine that wrote it. */
    record Channel(String id, String name) {
    }

    /**
     * A role as written in the file. {@code restricted == false} means every channel,
     * and then {@code channels} is empty.
     */
    record ExportedRole(String name, String description, List<String> permissions, boolean restricted,
            List<Channel> channels) {
    }

    record ExportFile(String formatVersion, String rbacVersion, String engineVersion, List<ExportedRole> roles) {
    }

    /** A file refused as a whole. The message is for the user. */
    static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;

        Refusal(String message) {
            super(message);
        }
    }

    private static final ErrorHandler THROW_ON_ERROR = new ErrorHandler() {
        @Override
        public void warning(SAXParseException e) {
        }

        @Override
        public void error(SAXParseException e) throws SAXException {
            throw e;
        }

        @Override
        public void fatalError(SAXParseException e) throws SAXException {
            throw e;
        }
    };

    private RoleTransferFormat() {
    }

    // ========== Writing ==========

    /**
     * @return the file's text
     * @throws IllegalArgumentException if a value holds a character XML can't carry;
     *                                  the message names the role
     */
    static String write(String rbacVersion, String engineVersion, List<ExportedRole> roles) {
        StringBuilder out = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.append("<rbacRoles formatVersion=\"").append(FORMAT_VERSION)
                .append("\" rbacVersion=\"").append(escape(rbacVersion))
                .append("\" engineVersion=\"").append(escape(engineVersion)).append("\">\n");
        for (ExportedRole role : roles) {
            try {
                writeRole(out, role);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("The role '" + role.name() + "' has a character a role export file"
                        + " can't hold, in " + e.getMessage() + ".", e);
            }
        }
        return out.append("</rbacRoles>\n").toString();
    }

    private static void writeRole(StringBuilder out, ExportedRole role) {
        out.append("  <role>\n");
        out.append("    <name>").append(escape(role.name(), "its name")).append("</name>\n");
        String description = role.description() != null ? role.description() : "";
        out.append("    <description>").append(escape(description, "its description")).append("</description>\n");
        if (role.permissions().isEmpty()) {
            out.append("    <permissions/>\n");
        } else {
            out.append("    <permissions>\n");
            for (String permission : role.permissions()) {
                out.append("      <permission>").append(escape(permission, "a permission")).append("</permission>\n");
            }
            out.append("    </permissions>\n");
        }
        if (role.channels().isEmpty()) {
            out.append("    <channels restricted=\"").append(role.restricted()).append("\"/>\n");
        } else {
            out.append("    <channels restricted=\"").append(role.restricted()).append("\">\n");
            for (Channel channel : role.channels()) {
                out.append("      <channel id=\"").append(escape(channel.id(), "a channel id"))
                        .append("\" name=\"").append(escape(channel.name(), "a channel name")).append("\"/>\n");
            }
            out.append("    </channels>\n");
        }
        out.append("  </role>\n");
    }

    private static String escape(String value) {
        return escape(value, "the file header");
    }

    /**
     * Escapes a value for an element or an attribute. Tab, line feed and carriage
     * return are written as character references so an attribute keeps them and a
     * carriage return isn't turned into a line feed.
     */
    private static String escape(String value, String where) {
        StringBuilder out = new StringBuilder(value.length());
        value.codePoints().forEach(c -> {
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\t', '\n', '\r' -> out.append("&#").append(c).append(';');
                default -> {
                    if (!isXmlChar(c)) {
                        throw new IllegalArgumentException(where);
                    }
                    out.appendCodePoint(c);
                }
            }
        });
        return out.toString();
    }

    /** XML 1.0's Char production. */
    private static boolean isXmlChar(int c) {
        return c == 0x9 || c == 0xA || c == 0xD
                || (c >= 0x20 && c <= 0xD7FF)
                || (c >= 0xE000 && c <= 0xFFFD)
                || (c >= 0x10000 && c <= 0x10FFFF);
    }

    // ========== Reading ==========

    /**
     * @param text the file's text
     * @return the file's contents
     * @throws Refusal if the file isn't one this rbac reads; the message says why
     */
    static ExportFile parse(String text) throws Refusal {
        if (text == null || text.isBlank()) {
            throw new Refusal("The file is empty.");
        }
        if (text.length() > MAX_CHARS) {
            throw new Refusal("The file is larger than 5 MB, far more than a role export needs.");
        }
        if (text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        Document document = parseDocument(text);
        Element root = document.getDocumentElement();
        if (!"rbacRoles".equals(root.getTagName())) {
            throw new Refusal("This isn't a role export file: its top element is <" + root.getTagName()
                    + ">, not <rbacRoles>.");
        }

        String formatVersion = attribute(root, "formatVersion");
        String rbacVersion = attribute(root, "rbacVersion");
        if (formatVersion == null) {
            throw new Refusal("The file doesn't say which format version it is, so this rbac can't tell whether it"
                    + " reads it.");
        }
        if (!FORMAT_VERSION.equals(formatVersion)) {
            throw new Refusal("This file is format " + formatVersion
                    + (rbacVersion != null ? ", written by rbac " + rbacVersion : "")
                    + ". This rbac reads format " + FORMAT_VERSION + ".");
        }
        // The parser also reads XML 1.1, which can carry control characters an export can't write back.
        if (!"1.0".equals(document.getXmlVersion())) {
            throw new Refusal("The file is XML " + document.getXmlVersion() + ". Role export files are XML 1.0.");
        }
        allowAttributes(root, "formatVersion", "rbacVersion", "engineVersion");
        rbacVersion = requireAttribute(root, "rbacVersion");
        String engineVersion = requireAttribute(root, "engineVersion");

        List<ExportedRole> roles = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (Element element : children(root, "<rbacRoles>")) {
            if (!"role".equals(element.getTagName())) {
                throw undefined(element, "<rbacRoles>");
            }
            ExportedRole role = parseRole(element, roles.size() + 1);
            // Exact, not ignoring case: Postgres, Derby and Oracle hold "Lab" and "LAB" as two roles, and their
            // export has to read back. Where the database holds two names as one, the import says so.
            if (!names.add(role.name())) {
                throw new Refusal("The file has more than one role named '" + role.name() + "'.");
            }
            roles.add(role);
        }
        if (roles.isEmpty()) {
            throw new Refusal("The file has no roles.");
        }
        return new ExportFile(formatVersion, rbacVersion, engineVersion, roles);
    }

    private static ExportedRole parseRole(Element element, int position) throws Refusal {
        String where = "role " + position;
        allowAttributes(element);
        Map<String, Element> fields = new HashMap<>();
        for (Element child : children(element, where)) {
            String tag = child.getTagName();
            if (!Set.of("name", "description", "permissions", "channels").contains(tag)) {
                throw undefined(child, where);
            }
            if (fields.put(tag, child) != null) {
                throw new Refusal("Role " + position + " in the file has more than one <" + tag + ">.");
            }
        }

        String name = leafText(require(fields, "name", where), where);
        if (name.isBlank()) {
            throw new Refusal("Role " + position + " in the file has an empty name.");
        }
        if (name.length() > MAX_NAME) {
            throw new Refusal("Role " + position + " in the file has a name longer than " + MAX_NAME + " characters.");
        }
        where = "the role '" + name + "'";

        String description = fields.containsKey("description") ? leafText(fields.get("description"), where) : "";
        if (description.length() > MAX_DESCRIPTION) {
            throw new Refusal("The role '" + name + "' has a description longer than " + MAX_DESCRIPTION
                    + " characters.");
        }

        List<String> permissions = parsePermissions(require(fields, "permissions", where), name, where);

        Element channelsElement = require(fields, "channels", where);
        allowAttributes(channelsElement, "restricted");
        String restrictedText = requireAttribute(channelsElement, "restricted");
        if (!"true".equals(restrictedText) && !"false".equals(restrictedText)) {
            throw new Refusal("The role '" + name + "' has restricted=\"" + restrictedText
                    + "\" on <channels>; it must be true or false.");
        }
        boolean restricted = Boolean.parseBoolean(restrictedText);
        List<Channel> channels = parseChannels(channelsElement, name, where);
        if (!restricted && !channels.isEmpty()) {
            throw new Refusal("The role '" + name + "' sees every channel (restricted=\"false\") but also lists"
                    + " channels.");
        }
        if (restricted && channels.isEmpty()) {
            throw new Refusal("The role '" + name + "' is restricted to channels but lists none.");
        }
        return new ExportedRole(name, description, permissions, restricted, channels);
    }

    private static List<String> parsePermissions(Element permissionsElement, String name, String where)
            throws Refusal {
        allowAttributes(permissionsElement);
        List<String> permissions = new ArrayList<>();
        for (Element child : children(permissionsElement, where)) {
            if (!"permission".equals(child.getTagName())) {
                throw undefined(child, where);
            }
            String permission = leafText(child, where);
            if (permission.isBlank()) {
                throw new Refusal("The role '" + name + "' has an empty permission.");
            }
            if (permission.length() > MAX_PERMISSION) {
                throw new Refusal("The role '" + name + "' has a permission longer than " + MAX_PERMISSION
                        + " characters.");
            }
            if (permissions.contains(permission)) {
                throw new Refusal("The role '" + name + "' lists the permission '" + permission + "' twice.");
            }
            permissions.add(permission);
        }
        return permissions;
    }

    private static List<Channel> parseChannels(Element channelsElement, String name, String where) throws Refusal {
        List<Channel> channels = new ArrayList<>();
        Set<String> channelIds = new HashSet<>();
        for (Element child : children(channelsElement, where)) {
            if (!"channel".equals(child.getTagName())) {
                throw undefined(child, where);
            }
            allowAttributes(child, "id", "name");
            if (!children(child, where).isEmpty()) {
                throw new Refusal("A <channel> in the role '" + name + "' has content; format 1 channels are empty"
                        + " elements.");
            }
            String id = requireAttribute(child, "id");
            if (id.isBlank()) {
                throw new Refusal("A channel in the role '" + name + "' has an empty id.");
            }
            if (!channelIds.add(id)) {
                throw new Refusal("The role '" + name + "' lists the channel " + id + " twice.");
            }
            channels.add(new Channel(id, requireAttribute(child, "name")));
        }
        return channels;
    }

    private static Document parseDocument(String text) throws Refusal {
        DocumentBuilder builder;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("The server's XML parser can't be set up to read role files safely", e);
        }
        // The default handler prints parse errors to stderr before throwing.
        builder.setErrorHandler(THROW_ON_ERROR);
        try {
            return builder.parse(new InputSource(new StringReader(text)));
        } catch (SAXParseException e) {
            if (String.valueOf(e.getMessage()).contains("DOCTYPE")) {
                throw new Refusal("The file has a DOCTYPE. Role export files never have one, so it isn't read.");
            }
            throw new Refusal("The file isn't well-formed XML (line " + e.getLineNumber() + "): " + e.getMessage());
        } catch (SAXException e) {
            throw new Refusal("The file isn't well-formed XML: " + e.getMessage());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns an element's child elements. Whitespace between them and comments are
     * allowed; text or anything else is refused.
     */
    private static List<Element> children(Element parent, String where) throws Refusal {
        List<Element> elements = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            switch (node.getNodeType()) {
                case Node.ELEMENT_NODE -> elements.add((Element) node);
                case Node.COMMENT_NODE -> {
                }
                case Node.TEXT_NODE, Node.CDATA_SECTION_NODE -> {
                    if (!node.getNodeValue().isBlank()) {
                        throw new Refusal("The file has text inside <" + parent.getTagName() + "> in " + where
                                + ", where format 1 has none.");
                    }
                }
                default -> throw new Refusal("The file has something inside <" + parent.getTagName() + "> in " + where
                        + " that format 1 doesn't define.");
            }
        }
        return elements;
    }

    /** The text of an element that may hold only text. */
    private static String leafText(Element element, String where) throws Refusal {
        allowAttributes(element);
        List<Element> nested = childElements(element);
        if (!nested.isEmpty()) {
            throw undefined(nested.get(0), where);
        }
        return element.getTextContent();
    }

    /** Returns an element's child elements, ignoring everything else. */
    private static List<Element> childElements(Element parent) {
        List<Element> elements = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
                elements.add((Element) nodes.item(i));
            }
        }
        return elements;
    }

    private static Element require(Map<String, Element> fields, String tag, String where) throws Refusal {
        Element element = fields.get(tag);
        if (element == null) {
            throw new Refusal("In the file, " + where + " has no <" + tag + ">, which format 1 requires.");
        }
        return element;
    }

    private static String attribute(Element element, String name) {
        return element.hasAttribute(name) ? element.getAttribute(name) : null;
    }

    private static String requireAttribute(Element element, String name) throws Refusal {
        String value = attribute(element, name);
        if (value == null) {
            throw new Refusal("The file has a <" + element.getTagName() + "> without its " + name
                    + " attribute, which format 1 requires.");
        }
        return value;
    }

    private static void allowAttributes(Element element, String... allowed) throws Refusal {
        List<String> names = Arrays.asList(allowed);
        NamedNodeMap attributes = element.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            String name = attributes.item(i).getNodeName();
            if (!names.contains(name)) {
                throw new Refusal("The file has the attribute " + name + " on <" + element.getTagName()
                        + ">, which format 1 doesn't define.");
            }
        }
    }

    private static Refusal undefined(Element element, String where) {
        return new Refusal("The file has <" + element.getTagName() + "> in " + where
                + ", which format 1 doesn't define.");
    }
}
