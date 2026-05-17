// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.ui.AbstractSettingsPanel;
import com.mirth.connect.client.ui.AuthorizationControllerFactory;
import com.mirth.connect.model.converters.ObjectXMLSerializer;
import com.mirth.connect.plugins.SettingsPanelPlugin;
import com.mirth.connect.plugins.auth.client.SecureAuthorizationController;

/**
 * Client-side plugin entry point. Registered via {@code <clientClasses>} in
 * {@code plugin.xml}.
 *
 * <p>Does three things at construction time:</p>
 * <ol>
 *   <li>Whitelists the plugin's model classes with the client-side XStream
 *       serializer (mirrors {@code RbacServicePlugin.start} on the server)</li>
 *   <li>Installs {@link SecureAuthorizationController} into the engine's
 *       client-side authorization factory via reflection — see
 *       {@link #installAuthorizationController()} for why this is necessary</li>
 *   <li>Builds the RBAC settings panel that shows up in the Settings tab</li>
 * </ol>
 */
public class RbacClientPlugin extends SettingsPanelPlugin {

    private static final Logger log = LoggerFactory.getLogger(RbacClientPlugin.class);

    private final AbstractSettingsPanel settingsPanel;

    /**
     * @param name the plugin point name supplied by the engine (matches
     *             {@code RbacServletInterface.PLUGIN_NAME})
     */
    public RbacClientPlugin(String name) {
        super(name);
        ObjectXMLSerializer.getInstance().allowTypes(Collections.emptyList(),
                Arrays.asList(Role.class.getPackage().getName() + ".**"),
                Collections.emptyList());
        installAuthorizationController();
        settingsPanel = new RbacSettingsPanel(RbacServletInterface.PLUGIN_NAME);
    }

    /**
     * Forces our {@link SecureAuthorizationController} into the engine's
     * static singleton field on {@link AuthorizationControllerFactory}.
     *
     * <p>This is a DETERMINISTIC OVERRIDE, not a workaround for a load failure.
     * In 4.6.0 the factory's own path ({@code Class.forName(...)}) can very
     * likely construct a {@code SecureAuthorizationController} on its own — it
     * loads this plugin's client classes from the same classloader
     * {@code LoadedExtensions} uses to build this very plugin, gated on the
     * plugin name being present in the metadata map. We inject anyway so the
     * controller is installed deterministically and early: the factory only
     * assigns inside {@code if (authorizationController == null)}, and its first
     * call (Frame setup) precedes plugin construction. The observable cost of the
     * injection when the factory would have loaded it too is one harmless
     * duplicate permission fetch at startup, not a double-install.</p>
     *
     * <p>Failure mode if this breaks (e.g., the engine refactors the field
     * name): we log an error and fall back to the engine's default
     * controller, which allows everything client-side — the server-side
     * controller still enforces. UI may show buttons the server will then
     * deny, but no privilege escalation.</p>
     */
    private void installAuthorizationController() {
        try {
            Field field = AuthorizationControllerFactory.class.getDeclaredField("authorizationController");
            field.setAccessible(true);
            field.set(null, new SecureAuthorizationController());
            log.info("RBAC: Installed SecureAuthorizationController");
        } catch (Exception e) {
            log.error("RBAC: Failed to install SecureAuthorizationController", e);
        }
    }

    /**
     * Removes our {@link SecureAuthorizationController} from the factory's static
     * field on plugin shutdown (logout), but only if the field still holds OUR
     * instance.
     *
     * <p>Without this, the installed controller outlived logout: because the
     * factory only assigns when the field is {@code null}, a same-JVM re-login to
     * a server that does NOT have RBAC would keep enforcing the stale controller,
     * fail-closing the entire UI until the client process was restarted. Nulling
     * the field lets the next login re-evaluate against the new server — our
     * constructor reinstalls us if RBAC is present, or the engine installs its
     * default (allow-all client-side) controller if it is not.</p>
     *
     * <p>The {@code instanceof} guard ensures we never clobber a controller some
     * other path installed.</p>
     */
    private void uninstallAuthorizationController() {
        try {
            Field field = AuthorizationControllerFactory.class.getDeclaredField("authorizationController");
            field.setAccessible(true);
            Object current = field.get(null);
            if (current instanceof SecureAuthorizationController) {
                field.set(null, null);
                log.info("RBAC: Uninstalled SecureAuthorizationController");
            }
        } catch (Exception e) {
            log.error("RBAC: Failed to uninstall SecureAuthorizationController", e);
        }
    }

    /**
     * {@inheritDoc}
     * @return the RBAC settings panel, displayed as a tab under the
     *         Settings view in the administrator client
     */
    @Override
    public AbstractSettingsPanel getSettingsPanel() {
        return settingsPanel;
    }

    /**
     * {@inheritDoc}
     * <p>No-op: all initialization happens in the constructor so the
     * authorization controller is installed before any task panel renders.</p>
     */
    @Override
    public void start() {
    }

    /**
     * {@inheritDoc}
     * <p>Uninstalls our authorization controller from the factory's static field
     * so a same-JVM re-login (to this or a different server) starts from a clean
     * slate instead of inheriting a stale, possibly fail-closing controller.</p>
     */
    @Override
    public void stop() {
        uninstallAuthorizationController();
    }

    /**
     * {@inheritDoc}
     * <p>No-op: no state to reset (the settings panel manages its own
     * refresh).</p>
     */
    @Override
    public void reset() {
    }

    /**
     * {@inheritDoc}
     * @return the plugin display name (matches
     *         {@link RbacServletInterface#PLUGIN_NAME})
     */
    @Override
    public String getPluginPointName() {
        return RbacServletInterface.PLUGIN_NAME;
    }
}
