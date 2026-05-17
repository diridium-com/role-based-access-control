// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import static com.diridium.rbac.RbacServletInterface.PERMISSION_MANAGE;
import static com.diridium.rbac.RbacServletInterface.PERMISSION_VIEW;
import static com.diridium.rbac.RbacServletInterface.PLUGIN_NAME;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.core.api.util.OperationUtil;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.User;
import com.mirth.connect.model.converters.ObjectXMLSerializer;
import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * Server-side plugin lifecycle entry point.
 *
 * <p>Registered with the engine via {@code <serverClasses>} in
 * {@code plugin.xml}. The engine calls {@link #start} once on plugin startup
 * and {@link #stop} once on shutdown; everything else here exists to satisfy
 * the {@link ServicePlugin} contract.</p>
 *
 * <p>The two {@link ExtensionPermission} entries returned by
 * {@link #getExtensionPermissions()} appear in the engine's user-permissions
 * UI as "View Roles" and "Manage Roles" checkboxes; assigning them to a role
 * grants access to the corresponding subset of RBAC REST operations.</p>
 */
public class RbacServicePlugin implements ServicePlugin {

    private static final Logger log = LoggerFactory.getLogger(RbacServicePlugin.class);

    /**
     * {@inheritDoc}
     * @return the plugin display name shared with {@link RbacServletInterface#PLUGIN_NAME}
     */
    @Override
    public String getPluginPointName() {
        return PLUGIN_NAME;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Order of operations matters: we always whitelist serialization types
     * first so DTOs deserialize even when migration is broken (the admin UI
     * still needs to render error messages). Then the second-layer
     * migration check: re-read the schema_version property, and if it does
     * not match {@link RbacMigrator#LATEST_VERSION}, mark
     * {@link MigrationStatus} as failed and skip repository initialization.
     * The servlet then rejects every mutating call with a clear error
     * instead of letting requests hit potentially-broken persistence.</p>
     *
     * <p>Note that {@link RbacRepository#init} runs the admin-role seed, which
     * can itself flip {@link MigrationStatus} back to failed if the bootstrap
     * cannot complete — hence {@code markOk()} here is provisional until init
     * returns.</p>
     */
    @Override
    public void start() {
        ObjectXMLSerializer.getInstance().allowTypes(Collections.emptyList(),
                Arrays.asList(Role.class.getPackage().getName() + ".**"),
                Collections.emptyList());

        if (!verifyMigrationComplete()) {
            log.error("RBAC plugin disabled: schema migration did not reach v{}; see server logs and restart",
                    RbacMigrator.LATEST_VERSION);
            return;
        }
        MigrationStatus.markOk();
        // One-time orphan sweep: the engine deletes users without notifying RBAC (no FK,
        // no deletion hook), leaving rbac_user_role rows behind. Remove any assignment row
        // whose user no longer exists in the engine PERSON table, so a future reused id
        // cannot inherit a deleted user's role. Run BEFORE seeding so it only ever removes
        // pre-existing orphans and never a row the seeder just wrote. Self-contained
        // (PERSON-driven), so it is safe even if user enumeration below fails.
        RbacRepository.deleteOrphanUserRoles();
        RbacRepository.init(gatherExistingUserIds());
        log.info("RBAC plugin started");
    }

    /**
     * Collects the ids of every user currently known to the engine, so the
     * repository can assign them all to the admin role on first install
     * (preserving the access they had under OIE's default allow-all
     * controller). On failure returns an empty list; the seeder still floors
     * user 1.
     *
     * @return every engine user id, or an empty list if they could not be read
     */
    private List<Integer> gatherExistingUserIds() {
        try {
            List<User> users = ControllerFactory.getFactory().createUserController().getAllUsers();
            List<Integer> ids = new ArrayList<>();
            for (User user : users) {
                if (user.getId() != null) {
                    ids.add(user.getId());
                }
            }
            return ids;
        } catch (Exception e) {
            log.warn("RBAC: could not enumerate existing users for first-install seeding; "
                    + "user 1 will be seeded as the floor: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Reads the persisted schema_version and confirms it matches
     * {@link RbacMigrator#LATEST_VERSION}. Marks {@link MigrationStatus}
     * as failed if not, with a message that surfaces to admins via the
     * REST error.
     *
     * @return {@code true} if the schema version is current; {@code false}
     *         otherwise (and {@code MigrationStatus} has been marked failed)
     */
    boolean verifyMigrationComplete() {
        String raw = ConfigurationController.getInstance().getProperty(
                RbacServletInterface.PLUGIN_NAME, RbacMigrator.VERSION_PROPERTY);
        if (raw == null) {
            MigrationStatus.markFailed("schema_version property not set; the migrator did not run or failed silently");
            return false;
        }
        int current;
        try {
            current = Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            MigrationStatus.markFailed("schema_version property is not an integer: " + raw);
            return false;
        }
        if (current != RbacMigrator.LATEST_VERSION) {
            MigrationStatus.markFailed("schema_version is " + current + ", expected " + RbacMigrator.LATEST_VERSION);
            return false;
        }
        return true;
    }

    /**
     * {@inheritDoc}
     * <p>Tears down the repository singleton so a subsequent
     * {@code start} call starts cleanly. Also clears
     * {@link MigrationStatus} so a restart can re-evaluate the schema
     * state from scratch.</p>
     */
    @Override
    public void stop() {
        RbacRepository.close();
        MigrationStatus.markOk();
        log.info("RBAC plugin stopped");
    }

    /**
     * {@inheritDoc}
     * @param properties plugin properties from {@code plugin.xml} (unused)
     */
    @Override
    public void init(Properties properties) {
        // No properties needed
    }

    /**
     * {@inheritDoc}
     * @param properties incoming property updates (unused — RBAC has no runtime properties)
     */
    @Override
    public void update(Properties properties) {
        // No properties to update
    }

    /**
     * {@inheritDoc}
     * @return an empty {@link Properties} (RBAC declares no plugin-level settings)
     */
    @Override
    public Properties getDefaultProperties() {
        return new Properties();
    }

    /**
     * Declares the plugin's two extension permissions to the engine: VIEW and
     * MANAGE. Each is computed by reflecting over {@link RbacServletInterface}
     * for methods annotated with the matching permission name.
     *
     * <p>No task names are declared. RBAC's settings tab is gated client-side by
     * group-prefixed composite keys (see {@code SecureAuthorizationController}),
     * not by the bare {@code doRefresh}/{@code doSave} TaskConstants — and
     * declaring those bare names here collided with the engine's Data Pruner,
     * which registers the identical task keys (last-writer-wins). The shared
     * {@code getPluginProperties}/{@code setPluginProperties} operations are also
     * intentionally not claimed: RBAC never serves them (it persists via its own
     * {@code /roles} REST calls), and claiming them collided with Data Pruner too.</p>
     *
     * @return two-element array — view permission first, then manage permission
     */
    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        ExtensionPermission viewPermission = new ExtensionPermission(
                PLUGIN_NAME,
                PERMISSION_VIEW,
                "Displays RBAC role definitions and user assignments.",
                OperationUtil.getOperationNamesForPermission(PERMISSION_VIEW, RbacServletInterface.class),
                new String[0]
        );

        ExtensionPermission managePermission = new ExtensionPermission(
                PLUGIN_NAME,
                PERMISSION_MANAGE,
                "Allows creating, editing, and deleting roles, and assigning roles to users.",
                OperationUtil.getOperationNamesForPermission(PERMISSION_MANAGE, RbacServletInterface.class),
                new String[0]
        );

        return new ExtensionPermission[] { viewPermission, managePermission };
    }
}
