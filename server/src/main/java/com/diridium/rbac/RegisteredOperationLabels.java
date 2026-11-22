// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.core.Version;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.model.ApiProvider;
import com.mirth.connect.model.MetaData;
import com.mirth.connect.server.controllers.ExtensionController;

/**
 * Reads the permission each extension servlet operation declares in its {@code @MirthOperation}
 * label, from the servlet interfaces the extensions register with the engine: each enabled
 * extension's {@code apiProvider} entries of type {@code SERVLET_INTERFACE}, the same list the
 * engine's web server serves. The engine's own reader of these labels
 * ({@code OperationUtil.getOperationNamesForPermission}) only looks at the core API package, so
 * without this an extension's labels, the built-in connectors' included, never reach rbac.
 *
 * <p>The engine delivers an extension servlet's operation as an {@code ExtensionOperation} named
 * {@code <extension name>#<operation>}, where the extension name is what the servlet passes to
 * {@code MirthServlet}: by convention its interface's {@code PLUGIN_POINT} constant. Each label is
 * keyed that way. An interface with no {@code PLUGIN_POINT} String constant is skipped, because the
 * runtime names of its operations can't be known from the registration. rbac keeps nothing of
 * this beyond the map built at startup.
 */
final class RegisteredOperationLabels {

    private static final Logger log = LoggerFactory.getLogger(RegisteredOperationLabels.class);

    private RegisteredOperationLabels() {
    }

    /**
     * @param extensions the engine's extension controller; {@code null} gives an empty map
     * @return the label of every labelled operation of every enabled extension's registered
     *         servlet interfaces, keyed {@code PLUGIN_POINT#operation}
     */
    static Map<String, String> read(ExtensionController extensions) {
        Map<String, String> labels = new HashMap<>();
        if (extensions == null) {
            return labels;
        }
        // A fixed order, so that if two interfaces ever give one runtime name different labels,
        // which one rbac uses doesn't depend on map iteration order.
        List<MetaData> registered = new ArrayList<>();
        if (extensions.getPluginMetaData() != null) {
            registered.addAll(extensions.getPluginMetaData().values());
        }
        if (extensions.getConnectorMetaData() != null) {
            registered.addAll(extensions.getConnectorMetaData().values());
        }
        registered.sort(Comparator.comparing(MetaData::getName, Comparator.nullsLast(Comparator.naturalOrder())));

        for (MetaData metaData : registered) {
            if (!extensions.isExtensionEnabled(metaData.getName())) {
                continue;
            }
            List<ApiProvider> providers = new ArrayList<>(metaData.getApiProviders(Version.getLatest()));
            providers.sort(Comparator.comparing(ApiProvider::getName, Comparator.nullsLast(Comparator.naturalOrder())));
            for (ApiProvider provider : providers) {
                if (provider.getType() != ApiProvider.Type.SERVLET_INTERFACE) {
                    continue;
                }
                // One registration that can't be read costs only its own entries. LinkageError covers an
                // extension jar that is missing a class or was built against another engine.
                try {
                    addLabels(Class.forName(provider.getName(), false, RegisteredOperationLabels.class.getClassLoader()),
                            labels);
                } catch (Exception | LinkageError e) {
                    log.error("Could not read the permission labels of {}, which {} registers", provider.getName(),
                            metaData.getName(), e);
                }
            }
        }
        return labels;
    }

    /** Adds one servlet interface's labelled operations to {@code labels}. */
    static void addLabels(Class<?> servletInterface, Map<String, String> labels) {
        String extensionName = pluginPoint(servletInterface);
        if (extensionName == null) {
            log.debug("{} has no PLUGIN_POINT constant, so its operations' labels are not read", servletInterface.getName());
            return;
        }
        for (Method method : servletInterface.getMethods()) {
            MirthOperation operation = method.getAnnotation(MirthOperation.class);
            if (operation == null || operation.permission().isBlank()) {
                continue;
            }
            String key = extensionName + "#" + operation.name();
            String earlier = labels.putIfAbsent(key, operation.permission());
            if (earlier != null && !earlier.equals(operation.permission())) {
                log.warn("Operation {} is labelled both '{}' and '{}'; rbac uses '{}'", key, earlier,
                        operation.permission(), earlier);
            }
        }
    }

    private static String pluginPoint(Class<?> servletInterface) {
        try {
            Field field = servletInterface.getField("PLUGIN_POINT");
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                Object value = field.get(null);
                if (value instanceof String name && !name.isBlank()) {
                    return name;
                }
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            // No usable constant: the caller skips the interface.
        }
        return null;
    }
}
