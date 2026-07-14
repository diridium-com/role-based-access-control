// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.Operation.ExecuteType;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;
import com.mirth.connect.client.core.api.Param;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST contract for the RBAC plugin. Mounted at {@code /extensions/rbac}
 * and consumed by both the Swing administrator UI and any external client
 * that wants to manage RBAC programmatically.
 *
 * <p>Every operation here is gated by either {@link #PERMISSION_VIEW} or
 * {@link #PERMISSION_MANAGE}, declared as extension permissions by
 * {@code RbacServicePlugin}. The engine applies the gate before our servlet
 * implementation method runs; admins (users assigned to a role flagged
 * {@code is_admin=true}) bypass the gate via {@code RbacAuthorizationController}.</p>
 */
@Path("/extensions/rbac")
@Tag(name = "Role-Based Access Control")
@Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
@Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
public interface RbacServletInterface extends BaseServletInterface {

    /** Plugin display name; used by the engine's extension framework. */
    String PLUGIN_NAME = "Role-Based Access Control";

    /** Extension permission required for read operations (list/get role, list users, etc.). */
    String PERMISSION_VIEW = "View Roles";

    /** Extension permission required for mutating operations (create/update/delete/assign). */
    String PERMISSION_MANAGE = "Manage Roles";

    // ========== Role CRUD ==========

    /**
     * Lists every role defined in the plugin.
     *
     * @return all roles in id order, including their permission and channel sets
     * @throws ClientException if the underlying persistence call fails
     */
    @GET
    @Path("/roles")
    @Operation(summary = "Returns a list of all roles")
    @MirthOperation(name = "getRoles", display = "Get all roles", permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    List<Role> getRoles() throws ClientException;

    /**
     * Fetches a single role by id, including its permissions and channel restrictions.
     *
     * @param roleId database id of the role to fetch
     * @return the role
     * @throws ClientException if no role exists with that id or if the
     *                         persistence call fails
     */
    @GET
    @Path("/roles/{roleId}")
    @Operation(summary = "Returns a role with its permissions and channel restrictions")
    @MirthOperation(name = "getRole", display = "Get role", permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    Role getRole(@Param("roleId") @Parameter(description = "The ID of the role", required = true) @PathParam("roleId") int roleId) throws ClientException;

    /**
     * Creates a new role. The {@code isAdmin} field on the input is ignored —
     * new roles created via this API are always non-admin.
     *
     * @param role the role to create; {@code id} is ignored and will be
     *             assigned by the database
     * @return the persisted role with its newly assigned {@code id}, returned
     *         as a defensive copy so callers cannot inadvertently mutate
     *         repository state
     * @throws ClientException on duplicate name or other persistence failure
     */
    @POST
    @Path("/roles")
    @Operation(summary = "Creates a new role")
    @MirthOperation(name = "createRole", display = "Create role", permission = PERMISSION_MANAGE, type = ExecuteType.SYNC)
    Role createRole(@Param("role") @Parameter(description = "The role to create", required = true) Role role) throws ClientException;

    /**
     * Updates an existing role's name, description, permissions, and channel
     * restrictions. The {@code is_admin} flag is never modified by this call.
     *
     * <p>When the role being updated is the admin role, {@code AdminRoleGuard}
     * enforces additional invariants: the full permission set must remain
     * granted and no channel restrictions may be added.</p>
     *
     * @param roleId database id of the role to update
     * @param role   new state for the role (id field is ignored)
     * @throws ClientException if the role doesn't exist, the update would
     *                         violate an admin invariant, or persistence fails
     */
    @PUT
    @Path("/roles/{roleId}")
    @Operation(summary = "Updates a role including permissions and channel restrictions")
    @MirthOperation(name = "updateRole", display = "Update role", permission = PERMISSION_MANAGE, type = ExecuteType.SYNC)
    void updateRole(@Param("roleId") @Parameter(description = "The ID of the role", required = true) @PathParam("roleId") int roleId,
                    @Param("role") @Parameter(description = "The updated role", required = true) Role role) throws ClientException;

    /**
     * Deletes a role. The admin role cannot be deleted.
     *
     * @param roleId database id of the role to delete
     * @throws ClientException if the role is the admin role or persistence fails
     */
    @DELETE
    @Path("/roles/{roleId}")
    @Operation(summary = "Deletes a role")
    @MirthOperation(name = "deleteRole", display = "Delete role", permission = PERMISSION_MANAGE, type = ExecuteType.SYNC)
    void deleteRole(@Param("roleId") @Parameter(description = "The ID of the role", required = true) @PathParam("roleId") int roleId) throws ClientException;

    // ========== User-Role Assignment ==========

    /**
     * Looks up the role currently assigned to a user.
     *
     * @param userId engine user id to look up
     * @return the role assigned to that user, or {@code null} if the user has
     *         no role assignment
     * @throws ClientException on persistence failure
     */
    @GET
    @Path("/users/{userId}/role")
    @Operation(summary = "Returns the role assigned to a user")
    @MirthOperation(name = "getUserRole", display = "Get user role", permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    Role getUserRole(@Param("userId") @Parameter(description = "The user ID", required = true) @PathParam("userId") int userId) throws ClientException;

    /**
     * Assigns a role to a user, replacing any prior assignment.
     *
     * <p>{@code AdminRoleGuard.validateUserRoleAssignment} runs first; if the
     * user is currently the last admin and this assignment would move them
     * off the admin role, it throws to preserve the admin-user floor.</p>
     *
     * @param userId engine user id receiving the assignment
     * @param roleId role id to assign
     * @throws ClientException if the assignment would violate the admin
     *                         floor or persistence fails
     */
    @POST
    @Path("/users/{userId}/role/{roleId}")
    @Operation(summary = "Assigns a role to a user")
    @MirthOperation(name = "assignUserRole", display = "Assign user role", permission = PERMISSION_MANAGE, type = ExecuteType.SYNC)
    void assignUserRole(@Param("userId") @Parameter(description = "The user ID", required = true) @PathParam("userId") int userId,
                        @Param("roleId") @Parameter(description = "The role ID", required = true) @PathParam("roleId") int roleId) throws ClientException;

    /**
     * Removes a user's role assignment entirely; afterwards the user holds
     * no role and is denied every gated operation.
     *
     * <p>{@code AdminRoleGuard.validateUserRoleRemoval} runs first; if the
     * user is the last admin, it throws to preserve the admin-user floor.</p>
     *
     * @param userId engine user id whose role assignment is being removed
     * @throws ClientException if removing the assignment would leave zero
     *                         admins or persistence fails
     */
    @DELETE
    @Path("/users/{userId}/role")
    @Operation(summary = "Removes the role assignment from a user")
    @MirthOperation(name = "removeUserRole", display = "Remove user role", permission = PERMISSION_MANAGE, type = ExecuteType.SYNC)
    void removeUserRole(@Param("userId") @Parameter(description = "The user ID", required = true) @PathParam("userId") int userId) throws ClientException;

    // ========== Permission Discovery ==========

    /**
     * Returns the catalog of permissions the role editor UI offers as a
     * checklist: every core permission the engine declares, plus the display
     * names of every registered extension permission.
     *
     * @return the union of core permission constants from the engine's
     *         {@code Permissions} class and registered extension permission
     *         display names
     * @throws ClientException on reflection failure (highly unlikely)
     */
    @GET
    @Path("/permissions")
    @Operation(summary = "Returns all available permissions (core and extension)")
    @MirthOperation(name = "getAvailablePermissions", display = "Get available permissions", permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    Set<String> getAvailablePermissions() throws ClientException;

    /**
     * Returns the permissions effectively granted to the calling user. Used
     * by the client-side authorization controller to gate UI elements
     * (buttons, menu items, tasks) without making a permission check
     * round-trip for every one of them.
     *
     * <p>If the caller is an admin (assigned to a role flagged
     * {@code is_admin=true}), this returns the union of every core
     * permission plus every registered extension permission, so the UI
     * shows everything.</p>
     *
     * @return the set of permission identifiers the caller currently holds;
     *         empty if the caller has no role assignment
     * @throws ClientException on persistence failure
     */
    @GET
    @Path("/my-permissions")
    @Operation(summary = "Returns the granted permissions for the currently authenticated user")
    @MirthOperation(name = "getMyPermissions", display = "Get my permissions", permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    Set<String> getMyPermissions() throws ClientException;

    /**
     * Returns the task-name → permission-name mappings declared by installed
     * plugins via their {@code ExtensionPermission.getTaskNames()} arrays.
     *
     * <p>The client merges this into its own task-permission maps so plugin
     * buttons and settings tabs can be gated without our plugin hardcoding
     * plugin-specific entries. Keys may be a bare task name or a
     * {@code "group/task"} composite. An empty map is returned if no
     * installed plugin has declared task names.</p>
     *
     * @return immutable snapshot of the current task-permission mappings
     * @throws ClientException on internal failure
     */
    @GET
    @Path("/task-permissions")
    @Operation(summary = "Returns task-name to permission mappings declared by installed extensions")
    @MirthOperation(name = "getExtensionTaskPermissions", display = "Get extension task permissions",
            permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    Map<String, String> getExtensionTaskPermissions() throws ClientException;

    /**
     * Returns each extension permission's publishing plugin, keyed by
     * permission display name (e.g. {@code "View Thread Dump" → "Thread
     * Viewer"}).
     *
     * <p>The role editors use this to render plugin permissions under the
     * plugin's own header instead of a generic bucket. An empty map is
     * returned if no installed plugin has declared permissions.</p>
     *
     * @return immutable snapshot of permission → plugin-name mappings
     * @throws ClientException on internal failure
     */
    @GET
    @Path("/permissions/extensions")
    @Operation(summary = "Returns extension-permission to publishing-plugin mappings")
    @MirthOperation(name = "getExtensionPermissionGroups", display = "Get extension permission groups",
            permission = PERMISSION_VIEW, type = ExecuteType.ASYNC, auditable = false)
    Map<String, String> getExtensionPermissionGroups() throws ClientException;
}
