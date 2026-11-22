// SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.model.ApiProvider;
import com.mirth.connect.model.ConnectorMetaData;
import com.mirth.connect.model.PluginMetaData;
import com.mirth.connect.server.controllers.ExtensionController;

class RegisteredOperationLabelsTest {

    /** Shaped like a connector's servlet interface: a PLUGIN_POINT and labelled operations. */
    public interface LabelledService {
        String PLUGIN_POINT = "Test Connector Service";

        @MirthOperation(name = "testConnection", display = "Test", permission = "manageChannels")
        void testConnection();

        @MirthOperation(name = "getTemplates", display = "Templates", permission = "viewChannels")
        void getTemplates();

        @MirthOperation(name = "unlabelled", display = "Unlabelled")
        void unlabelled();
    }

    /** Another interface giving one runtime name of LabelledService a different label. */
    public interface ClashingService {
        String PLUGIN_POINT = "Test Connector Service";

        @MirthOperation(name = "testConnection", display = "Test", permission = "viewChannels")
        void testConnection();
    }

    /** Labelled with a permission that is neither core nor registered by any extension. */
    public interface UngrantableLabel {
        String PLUGIN_POINT = "Odd Service";

        @MirthOperation(name = "doThing", display = "Do Thing", permission = "No Such Permission")
        void doThing();
    }

    /** Labelled, but no PLUGIN_POINT, so the runtime names can't be known. */
    public interface NoPluginPoint {
        @MirthOperation(name = "something", display = "Something", permission = "manageChannels")
        void something();
    }

    /** A PLUGIN_POINT that isn't a String. */
    public interface WrongPluginPointType {
        int PLUGIN_POINT = 7;

        @MirthOperation(name = "something", display = "Something", permission = "manageChannels")
        void something();
    }

    private static ApiProvider provider(ApiProvider.Type type, String name) {
        ApiProvider provider = new ApiProvider();
        provider.setType(type);
        provider.setName(name);
        return provider;
    }

    private static ConnectorMetaData connector(String name, ApiProvider... providers) {
        ConnectorMetaData metaData = new ConnectorMetaData();
        metaData.setName(name);
        metaData.setApiProviders(List.of(providers));
        return metaData;
    }

    private static PluginMetaData plugin(String name, ApiProvider... providers) {
        PluginMetaData metaData = new PluginMetaData();
        metaData.setName(name);
        metaData.setApiProviders(List.of(providers));
        return metaData;
    }

    private static ExtensionController extensions(List<ConnectorMetaData> connectors, List<PluginMetaData> plugins,
            String... enabled) {
        ExtensionController controller = mock(ExtensionController.class);
        Map<String, ConnectorMetaData> connectorMap = new HashMap<>();
        connectors.forEach(c -> connectorMap.put(c.getName(), c));
        Map<String, PluginMetaData> pluginMap = new HashMap<>();
        plugins.forEach(p -> pluginMap.put(p.getName(), p));
        when(controller.getConnectorMetaData()).thenReturn(connectorMap);
        when(controller.getPluginMetaData()).thenReturn(pluginMap);
        for (String name : enabled) {
            when(controller.isExtensionEnabled(name)).thenReturn(true);
        }
        return controller;
    }

    @Test
    void addLabels_keysEachLabelledOperationByPluginPointAndName() {
        Map<String, String> labels = new HashMap<>();
        RegisteredOperationLabels.addLabels(LabelledService.class, labels);
        assertEquals(Map.of("Test Connector Service#testConnection", "manageChannels",
                "Test Connector Service#getTemplates", "viewChannels"), labels);
    }

    @Test
    void addLabels_skipsAnInterfaceWithoutAStringPluginPoint() {
        Map<String, String> labels = new HashMap<>();
        RegisteredOperationLabels.addLabels(NoPluginPoint.class, labels);
        RegisteredOperationLabels.addLabels(WrongPluginPointType.class, labels);
        assertTrue(labels.isEmpty(), labels.toString());
    }

    @Test
    void addLabels_keepsTheFirstLabelWhenTwoInterfacesClash() {
        Map<String, String> labels = new HashMap<>();
        RegisteredOperationLabels.addLabels(LabelledService.class, labels);
        RegisteredOperationLabels.addLabels(ClashingService.class, labels);
        assertEquals("manageChannels", labels.get("Test Connector Service#testConnection"));
    }

    @Test
    void read_noExtensionController_isEmpty() {
        assertTrue(RegisteredOperationLabels.read(null).isEmpty());
    }

    @Test
    void read_readsRegisteredServletInterfacesOfConnectorsAndPlugins() {
        ExtensionController controller = extensions(
                List.of(connector("Test Writer", provider(ApiProvider.Type.SERVLET_INTERFACE, LabelledService.class.getName()))),
                List.of(plugin("Test Plugin", provider(ApiProvider.Type.SERVLET_INTERFACE, ClashingService.class.getName()))),
                "Test Writer", "Test Plugin");
        Map<String, String> labels = RegisteredOperationLabels.read(controller);
        // Both registrations are read; on the clash, extensions are read in name order, so
        // "Test Plugin" (ClashingService) comes before "Test Writer" (LabelledService).
        assertEquals("viewChannels", labels.get("Test Connector Service#testConnection"));
        assertEquals("viewChannels", labels.get("Test Connector Service#getTemplates"));
    }

    @Test
    void read_skipsDisabledExtensions() {
        ExtensionController controller = extensions(
                List.of(connector("Test Writer", provider(ApiProvider.Type.SERVLET_INTERFACE, LabelledService.class.getName()))),
                List.of());
        assertTrue(RegisteredOperationLabels.read(controller).isEmpty());
    }

    @Test
    void read_readsOnlyServletInterfaceRegistrations() {
        ExtensionController controller = extensions(
                List.of(connector("Test Writer", provider(ApiProvider.Type.SERVER_CLASS, LabelledService.class.getName()),
                        provider(ApiProvider.Type.SERVLET_INTERFACE_PACKAGE, "com.diridium.rbac"))),
                List.of(), "Test Writer");
        assertTrue(RegisteredOperationLabels.read(controller).isEmpty());
    }

    @Test
    void read_aRegistrationThatCannotBeLoadedCostsOnlyItsOwnEntries() {
        ExtensionController controller = extensions(
                List.of(connector("Test Writer", provider(ApiProvider.Type.SERVLET_INTERFACE, "com.example.Missing"),
                        provider(ApiProvider.Type.SERVLET_INTERFACE, LabelledService.class.getName()))),
                List.of(), "Test Writer");
        assertEquals("manageChannels", RegisteredOperationLabels.read(controller).get("Test Connector Service#testConnection"));
    }
}
