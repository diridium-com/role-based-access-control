// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

package com.diridium.rbac;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.client.core.Operation;
import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.client.core.api.util.OperationUtil;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.server.controllers.AuthorizationController;
import com.mirth.connect.server.controllers.ChannelAuthorizer;

public class RbacAuthorizationController extends AuthorizationController {

    private static final Logger log = LoggerFactory.getLogger(RbacAuthorizationController.class);

    // Operations required by the UI during login/setup - allowed for all authenticated users.
    //
    // getMyPermissions / getExtensionTaskPermissions are served by RBAC's OWN extension
    // servlet, so at runtime the engine delivers them as the composite "<pluginName>#<op>"
    // name (ExtensionOperation.getName()). The composite entries below are what actually
    // match at runtime and let a no-role user bootstrap the client UI; the bare entries
    // never match at runtime but are kept so the whitelist unit test can assert them
    // without constructing an ExtensionOperation.
    //
    // getAllUsers/getUser and getServerSettings were deliberately REMOVED from this list:
    //   - getServerSettings leaks plaintext SMTP credentials; it is gated on
    //     SERVER_SETTINGS_VIEW by the engine and is not on any login/setup path, so it now
    //     falls through to the core permission map and is correctly denied without that grant.
    //   - getAllUsers/getUser are @DontCheckAuthorized in the engine and self-degrade when
    //     the controller reports "not authorized"; whitelisting them defeated that and exposed
    //     every user's record. They are handled via DEGRADABLE_OPERATIONS instead.
    private static final Set<String> INFRASTRUCTURE_OPERATIONS = new HashSet<>(Arrays.asList(
            "getMyPermissions",            // bare; inert at runtime, kept for the whitelist test
            "getExtensionTaskPermissions", // bare; inert at runtime, kept for the whitelist test
            RbacServletInterface.PLUGIN_NAME + "#getMyPermissions",            // composite; real match
            RbacServletInterface.PLUGIN_NAME + "#getExtensionTaskPermissions", // composite; real match
            "getStatus",                   // Server status checks
            "getServerId"                  // Server identification
    ));

    // Core engine read operations annotated @DontCheckAuthorized: the engine servlet calls
    // isUserAuthorized() itself and, when it returns false, degrades gracefully (empty list,
    // null, or self-only) instead of erroring. RBAC's normal denial path THROWS a 403 to
    // deliver a custom "Missing permission" reason, which for these ops would defeat the
    // engine's designed degradation and hard-fail partially-permissioned users (and break
    // limited-user login, which fetches getAllUsers). For these ops only, the denial path
    // returns false so the engine performs its own degradation.
    //
    // DRIFT HAZARD: this list is hand-maintained against the engine's @DontCheckAuthorized
    // read methods and must be re-verified on every engine bump. Adding an op that is NOT
    // @DontCheckAuthorized would be safe (it is only reached on the denial path) but pointless;
    // more importantly, every op here must genuinely self-degrade in its servlet.
    private static final Set<String> DEGRADABLE_OPERATIONS = new HashSet<>(Arrays.asList(
            "getChannels",            // ChannelServlet -> empty list
            "getChannel",             // ChannelServlet -> null
            "getConnectorNames",      // ChannelServlet -> empty
            "getMetaDataColumns",     // ChannelServlet -> empty
            "getChannelIdsAndNames",  // ChannelServlet -> empty map
            "getChannelPortsInUse",   // ChannelServlet -> empty
            "getChannelSummary",      // ChannelServlet -> empty
            "getAllUsers",            // UserServlet -> current user only
            "getUser",                // UserServlet -> self-only
            "getCodeTemplateSummary"  // CodeTemplateServlet -> empty
    ));

    // Operations a user can always perform against their own user record,
    // even without manageUsers. The forced password change on first login
    // (or after admin reset) calls updateUserPassword, which would otherwise
    // lock out any user whose role lacks manageUsers.
    private static final Set<String> SELF_USER_OPERATIONS = new HashSet<>(Arrays.asList(
            "updateUser",
            "updateUserPassword"
    ));

    // The engine operation that deletes a user. Guarded so the last admin user
    // cannot be removed via the Users panel, which would otherwise leave the
    // system with zero admins (rbac_user_role has no FK to the person table, so
    // RBAC never sees the deletion through its own role/assignment operations).
    private static final String REMOVE_USER_OPERATION = "removeUser";

    // Maps operation name -> permission string (e.g., "getChannel" -> "viewChannels")
    private final Map<String, String> operationToPermission = new ConcurrentHashMap<>();

    // Maps extension operation name -> extension permission display name
    private final Map<String, String> extensionOperationToPermission = new ConcurrentHashMap<>();

    // Maps extension task name (or "group/task" composite) -> permission display name.
    // Populated by addExtensionPermission from each ExtensionPermission's taskNames.
    // Exposed to the client so SecureAuthorizationController can gate plugin-supplied
    // task pane buttons and settings tabs without us hardcoding their names.
    private final Map<String, String> extensionTaskToPermission = new ConcurrentHashMap<>();

    // Cache: userId -> cached auth info
    private final ConcurrentHashMap<Integer, UserAuthCache> cache = new ConcurrentHashMap<>();

    /**
     * Builds the operation→permission map immediately so every later
     * {@link #isUserAuthorized} call is a pure map lookup. The engine's
     * {@code DefaultAuthorizationController.create} factory instantiates
     * this class once at server startup.
     */
    public RbacAuthorizationController() {
        super();
        buildOperationPermissionMap();
        log.info("RBAC AuthorizationController initialized");
    }

    private void buildOperationPermissionMap() {
        // For each core permission constant, use OperationUtil to find all operation names
        // that are annotated with that permission, then build the reverse map.
        //
        // The try-catch sits INSIDE the loop on purpose: operations left unmapped fall
        // into the "unknown operation -> allow" branch of isUserAuthorized, so a single
        // failed scan aborting the rest would silently weaken authorization for every
        // permission after the failure. One bad permission must cost only its own entries.
        Set<String> corePermissions = PermissionUtil.getAllCorePermissions();
        int failures = 0;
        for (String permissionName : corePermissions) {
            try {
                String[] opNames = OperationUtil.getOperationNamesForPermission(permissionName);
                for (String opName : opNames) {
                    operationToPermission.put(opName, permissionName);
                }
            } catch (Exception e) {
                failures++;
                log.error("Failed to map operations for permission '{}'", permissionName, e);
            }
        }
        if (failures > 0 || operationToPermission.isEmpty()) {
            log.error("Operation-to-permission map is DEGRADED: {} of {} permission scans failed, "
                    + "{} entries mapped. Operations gated by unmapped permissions will be allowed "
                    + "for any authenticated user.",
                    failures, corePermissions.size(), operationToPermission.size());
        } else {
            log.info("Built operation-to-permission map with {} entries", operationToPermission.size());
        }
    }

    /**
     * Decides whether a user may invoke a given operation.
     *
     * <p>Allow paths, in order:</p>
     * <ol>
     *   <li>The user is assigned to the admin role (full bypass)</li>
     *   <li>The {@code operation} is {@code null} (engine corner case)</li>
     *   <li>The operation name is on the infrastructure whitelist (login,
     *       getMyPermissions, etc.)</li>
     *   <li>The operation is a self-user edit and the target user id in
     *       {@code parameterMap} matches the caller</li>
     *   <li>The user's role grants the required permission (core or extension)</li>
     *   <li>The operation has no permission mapping at all (unknown
     *       operation; documented in the design review and intentionally
     *       allowed today)</li>
     * </ol>
     *
     * <p>Denial throws {@link MirthApiException} with a 403 status and a
     * custom reason phrase naming the missing permission, so the admin UI
     * can surface a meaningful error instead of a generic "forbidden".</p>
     *
     * @param userId       caller's engine user id; {@code null} treated as no role
     * @param operation    the operation being invoked (engine wraps the
     *                     @MirthOperation annotation into this); may be null
     * @param parameterMap operation parameter values keyed by their
     *                     {@code @Param} name; used by the self-edit
     *                     carve-out
     * @param address      caller's IP address (for the audit log only)
     * @param audit        if true, dispatch a {@code ServerEvent} describing
     *                     this authorization decision
     * @return always {@code true} when authorized
     * @throws ControllerException  for unexpected internal failures
     * @throws MirthApiException    (a {@code RuntimeException} subtype) with
     *                              a 403 status when denied
     */
    @Override
    public boolean isUserAuthorized(Integer userId, Operation operation, Map<String, Object> parameterMap, String address, boolean audit) throws ControllerException {
        // Lockout guard: refuse to delete the last admin user, even for admins.
        // This sits ahead of the admin bypass on purpose — an admin deleting the
        // only admin (including themselves) would otherwise lock everyone out.
        if (operation != null && REMOVE_USER_OPERATION.equals(operation.getName())
                && wouldRemoveLastAdmin(parameterMap)) {
            if (audit) {
                auditAuthorizationRequest(userId, operation, parameterMap, ServerEvent.Outcome.FAILURE, address);
            }
            log.warn("RBAC: blocked deletion of the last admin user");
            throw forbidden("Cannot delete the last administrator; assign another user to the Administrator role first");
        }

        // Admin bypass: anyone holding the admin role gets through.
        if (isAdminUser(userId)) {
            return auditAndAllow(audit, userId, operation, parameterMap, address);
        }

        if (operation == null) {
            return auditAndAllow(audit, userId, operation, parameterMap, address);
        }

        // Allow infrastructure operations needed for UI login/setup
        if (INFRASTRUCTURE_OPERATIONS.contains(operation.getName())) {
            return auditAndAllow(audit, userId, operation, parameterMap, address);
        }

        // A user can always edit their own user record (profile + password)
        // regardless of role. Required so the forced password change on first
        // login doesn't lock out users whose role lacks manageUsers.
        if (isSelfUserOperation(userId, operation, parameterMap)) {
            return auditAndAllow(audit, userId, operation, parameterMap, address);
        }

        String operationName = operation.getName();
        boolean authorized = false;
        String deniedPermission = null;

        try {
            UserAuthCache userAuth = getUserAuth(userId);

            if (userAuth == null) {
                // No role assigned -> deny
                authorized = false;
                deniedPermission = "any (no role assigned)";
            } else {
                // First check extension permissions
                String extPermission = extensionOperationToPermission.get(operationName);
                if (extPermission != null) {
                    if (userAuth.grantedPermissions.contains(extPermission)) {
                        authorized = true;
                    } else {
                        deniedPermission = extPermission;
                    }
                } else {
                    // Check core permissions
                    String permissionName = operationToPermission.get(operationName);
                    if (permissionName != null) {
                        if (userAuth.grantedPermissions.contains(permissionName)) {
                            authorized = true;
                        } else {
                            deniedPermission = permissionName;
                        }
                    } else {
                        // Unknown operation — neither a core nor extension permission mapping was
                        // registered for it. Possible causes: (a) an engine endpoint added in a
                        // future version without updating our knowledge; (b) a plugin endpoint
                        // declared without a @MirthOperation permission; (c) an edge case we missed.
                        //
                        // Policy: allow. Defense-in-depth (deny) would break plugin operations
                        // whose permission we have not seen, which is a worse failure mode than
                        // letting an authenticated user with any role through. Log at debug so
                        // operators auditing the server can see what's slipping through.
                        log.warn("RBAC: allowing unknown operation '{}' for user {} (no permission mapping)",
                                operationName, userId);
                        authorized = true;
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error checking authorization for user {} operation {}", userId, operationName, e);
            deniedPermission = "unknown (error)";
        }

        if (authorized) {
            return auditAndAllow(audit, userId, operation, parameterMap, address);
        }

        // Denied: audit and log.
        if (audit) {
            auditAuthorizationRequest(userId, operation, parameterMap, ServerEvent.Outcome.FAILURE, address);
        }

        // For @DontCheckAuthorized engine reads, return false instead of throwing so the
        // engine servlet performs its own graceful degradation (empty result / self-only)
        // rather than surfacing a hard 403. Throwing here would defeat that design and, for
        // getAllUsers, break limited-user login. Gated ops still throw so the client shows
        // the descriptive "Missing permission" reason.
        if (DEGRADABLE_OPERATIONS.contains(operationName)) {
            log.debug("RBAC: User {} not authorized for degradable operation '{}'; returning false "
                    + "for engine-side graceful degradation", userId, operationName);
            return false;
        }

        log.warn("RBAC: User {} denied for operation '{}' (requires permission '{}')", userId, operationName, deniedPermission);
        throw forbidden("Missing permission: " + deniedPermission);
    }

    /**
     * Builds a {@link MirthApiException} carrying a 403 status with a custom
     * reason phrase. The {@code RuntimeException} nature bypasses
     * {@code MirthServlet}'s checked-exception handling so the reason phrase
     * reaches the client's error dialog intact.
     *
     * @param reason human-readable denial reason, surfaced to the client
     * @return the exception to throw
     */
    private static MirthApiException forbidden(String reason) {
        return new MirthApiException(Response.status(new Response.StatusType() {
            @Override
            public int getStatusCode() { return 403; }
            @Override
            public Response.Status.Family getFamily() { return Response.Status.Family.CLIENT_ERROR; }
            @Override
            public String getReasonPhrase() { return reason; }
        }).build());
    }

    /**
     * Determines whether a {@code removeUser} operation would delete the last
     * remaining administrator.
     *
     * @param parameterMap the operation parameters; the target user id is read
     *                     from the {@code "userId"} key
     * @return {@code true} only if the target user is currently assigned to the
     *         admin role and is the sole user holding it; {@code false} on any
     *         uncertainty (missing param, no admin role, RBAC not initialized,
     *         or a lookup error) so user management is never blocked spuriously
     */
    private boolean wouldRemoveLastAdmin(Map<String, Object> parameterMap) {
        if (parameterMap == null) {
            return false;
        }
        Object target = parameterMap.get("userId");
        if (!(target instanceof Integer targetUserId)) {
            return false;
        }
        try {
            RbacRepository repo = RbacRepository.getInstance();
            Integer adminRoleId = repo.getAdminRoleId();
            if (adminRoleId == null) {
                return false;
            }
            Integer targetRoleId = repo.getUserRoleId(targetUserId);
            if (targetRoleId == null || !targetRoleId.equals(adminRoleId)) {
                return false; // target user isn't an admin
            }
            return repo.countUsersByRoleId(adminRoleId) <= 1; // target is the last admin
        } catch (Exception e) {
            // RBAC not initialized or a lookup failed — don't block user management.
            log.debug("RBAC: could not evaluate the last-admin guard for user deletion", e);
            return false;
        }
    }

    /**
     * Registers a plugin-supplied extension permission so {@link #isUserAuthorized}
     * can check it. The engine invokes this once per registered permission
     * during extension startup.
     *
     * @param extensionPermission permission descriptor including its display
     *                            name (what users hold) and the operation names
     *                            it gates; {@code null} is silently ignored
     */
    @Override
    public void addExtensionPermission(ExtensionPermission extensionPermission) {
        if (extensionPermission == null) {
            return;
        }

        String permissionDisplayName = extensionPermission.getDisplayName();
        // Extension-servlet operations reach isUserAuthorized as the COMPOSITE name
        // "<extensionName>#<opName>" (the engine wraps them in ExtensionOperation, whose
        // getName() prepends the plugin name). Registering by the bare opName here caused
        // the lookup in isUserAuthorized to miss and fall through to the allow-unknown
        // fallback, leaving every extension's permission-gated endpoints unenforced -
        // including RBAC's own /roles management ops, which let any role-holder self-assign
        // the admin role. Keying by the composite name makes the lookup match and is
        // collision-free across plugins (a null/blank extensionName falls back to bare).
        String extensionName = extensionPermission.getExtensionName();
        String prefix = (extensionName != null && !extensionName.isEmpty()) ? extensionName + "#" : "";
        String[] operationNames = extensionPermission.getOperationNames();
        if (operationNames != null) {
            for (String opName : operationNames) {
                String key = prefix + opName;
                extensionOperationToPermission.put(key, permissionDisplayName);
                log.debug("Registered extension operation->permission: {} -> {}", key, permissionDisplayName);
            }
        }

        String[] taskNames = extensionPermission.getTaskNames();
        if (taskNames != null) {
            for (String taskName : taskNames) {
                extensionTaskToPermission.put(taskName, permissionDisplayName);
                log.debug("Registered extension task->permission: {} -> {}", taskName, permissionDisplayName);
            }
        }
    }

    /**
     * @param userId    caller's engine user id
     * @param operation the operation being invoked (ignored here; signature
     *                  required by the parent class)
     * @return {@code true} if the user's role limits them to a channel subset
     *         or the user has no role at all; {@code false} for admins and
     *         for users whose role has an empty channel-id set
     * @throws ControllerException for unexpected internal failures
     */
    @Override
    public boolean doesUserHaveChannelRestrictions(Integer userId, Operation operation) throws ControllerException {
        if (isAdminUser(userId)) {
            return false;
        }

        UserAuthCache userAuth = getUserAuth(userId);
        if (userAuth == null) {
            return true; // No role = restricted from everything
        }

        return userAuth.hasChannelRestrictions;
    }

    /**
     * Returns a predicate the engine uses to filter channel-scoped data
     * (dashboard listings, deploys, exports) per request.
     *
     * @param userId    caller's engine user id
     * @param operation the operation being invoked (ignored here)
     * @return {@code null} (meaning "no filtering, all channels visible") for
     *         admins and for users with unrestricted roles; a deny-all
     *         predicate for users with no role; a set-membership predicate
     *         for users with channel restrictions
     * @throws ControllerException for unexpected internal failures
     */
    @Override
    public ChannelAuthorizer getChannelAuthorizer(Integer userId, Operation operation) throws ControllerException {
        if (isAdminUser(userId)) {
            return null;
        }

        UserAuthCache userAuth = getUserAuth(userId);
        if (userAuth == null) {
            return channelId -> false;
        }

        if (!userAuth.hasChannelRestrictions) {
            return null;
        }

        Set<String> allowedChannels = userAuth.allowedChannelIds;
        return channelId -> allowedChannels.contains(channelId);
    }

    /**
     * Notification hook for engine-side username changes. RBAC keys all
     * its state by user id (never username), so this is a no-op.
     *
     * @param oldName the previous username (unused)
     * @param newName the new username (unused)
     */
    @Override
    public void usernameChanged(String oldName, String newName) throws ControllerException {
        // No-op: we use user IDs, not usernames
    }

    /**
     * Returns true if the user is currently assigned to the admin role.
     * The admin bypass replaces the prior hardcoded {@code userId == 1} check;
     * any user assigned to the role flagged {@code is_admin} skips permission
     * checks entirely.
     */
    boolean isAdminUser(Integer userId) {
        if (userId == null) {
            return false;
        }
        UserAuthCache userAuth = getUserAuth(userId);
        return userAuth != null && userAuth.isAdmin;
    }

    // ========== Cache Management ==========

    /**
     * Sentinel stored in the cache to represent "we looked this user up and
     * they have no role." {@link java.util.concurrent.ConcurrentHashMap#computeIfAbsent}
     * does not cache {@code null} returns, so without a sentinel every
     * authorization check for a no-role user would re-query the database.
     * {@link #getUserAuth} collapses this sentinel back to {@code null}
     * so the existing caller contract (null = deny) is unchanged.
     */
    private static final UserAuthCache NO_ROLE = new UserAuthCache();

    private UserAuthCache getUserAuth(Integer userId) {
        if (userId == null) {
            return null;
        }

        UserAuthCache cached = cache.computeIfAbsent(userId, this::loadUserAuth);
        return cached == NO_ROLE ? null : cached;
    }

    private UserAuthCache loadUserAuth(Integer userId) {
        try {
            RbacRepository repo = RbacRepository.getInstance();
            Integer roleId = repo.getUserRoleId(userId);
            if (roleId == null) {
                return NO_ROLE;
            }

            Role role = repo.getRoleById(roleId);
            if (role == null) {
                return NO_ROLE;
            }

            UserAuthCache authCache = new UserAuthCache();
            authCache.isAdmin = role.isAdmin();
            // Defensive copies — the cache must own its state, not share references
            // with Role instances that may be mutated elsewhere.
            authCache.grantedPermissions = role.getPermissions() != null
                    ? Set.copyOf(role.getPermissions())
                    : Set.of();

            Set<String> channelIds = role.getChannelIds();
            if (channelIds != null && !channelIds.isEmpty()) {
                authCache.hasChannelRestrictions = true;
                authCache.allowedChannelIds = Set.copyOf(channelIds);
            } else {
                authCache.hasChannelRestrictions = false;
                authCache.allowedChannelIds = Set.of();
            }

            return authCache;
        } catch (Exception e) {
            log.error("Failed to load auth cache for user {}", userId, e);
            return null;
        }
    }

    private boolean isSelfUserOperation(Integer callerUserId, Operation operation, Map<String, Object> parameterMap) {
        if (callerUserId == null || operation == null || parameterMap == null) {
            return false;
        }
        if (!SELF_USER_OPERATIONS.contains(operation.getName())) {
            return false;
        }
        Object target = parameterMap.get("userId");
        if (target instanceof Integer) {
            return callerUserId.equals(target);
        }
        return false;
    }

    /**
     * Used by {@code RbacServlet.getMyPermissions} to enumerate every
     * extension permission currently registered, so admin UI users see the
     * full set when their role is the admin role.
     *
     * @return distinct display names of every registered extension permission,
     *         in registration order (best-effort given that the underlying
     *         map is concurrent)
     */
    public Set<String> getExtensionPermissionNames() {
        return new LinkedHashSet<>(extensionOperationToPermission.values());
    }

    /**
     * Returns the task→permission mappings declared by installed plugins via
     * their {@link ExtensionPermission#getTaskNames()} arrays.
     *
     * <p>Keys may be a bare task name (e.g. {@code "viewChannelHistory"}) or a
     * group-prefixed composite (e.g. {@code "settings_FooPlugin/doRefresh"}).
     * The client merges this into its own task-permission maps so plugin
     * buttons and settings tabs can be gated client-side without us
     * hardcoding plugin-specific entries.</p>
     *
     * @return a fresh copy of the current map; never {@code null}
     */
    public Map<String, String> getExtensionTaskPermissions() {
        return new LinkedHashMap<>(extensionTaskToPermission);
    }

    /**
     * Dispatches a success audit event if requested and returns true. Used by
     * every "allow" branch of {@link #isUserAuthorized} so the success-audit
     * boilerplate lives in one place.
     */
    private boolean auditAndAllow(boolean audit, Integer userId, Operation operation,
                                   Map<String, Object> parameterMap, String address) {
        if (audit) {
            auditAuthorizationRequest(userId, operation, parameterMap, ServerEvent.Outcome.SUCCESS, address);
        }
        return true;
    }

    /**
     * Drops every cached user-auth entry. Called from {@code RbacServlet}
     * after any role or user-role mutation, so the next decision for any
     * user reflects the latest persistent state.
     */
    public void invalidateCache() {
        cache.clear();
        log.debug("RBAC auth cache invalidated");
    }

    /**
     * Drops one user's cached auth entry. Useful when a mutation is
     * known to affect a specific user (avoids hammering the DB for
     * unrelated users on the next request).
     *
     * @param userId engine user id whose cache entry should be removed;
     *               {@code null} is silently ignored
     */
    public void invalidateCache(Integer userId) {
        if (userId != null) {
            cache.remove(userId);
        }
    }

    // ========== Inner Classes ==========

    /**
     * Per-user authorization snapshot. Fields are set once in
     * {@link #loadUserAuth} and never mutated after the cache's
     * {@code put} publishes the reference. The {@code ConcurrentHashMap.put}
     * provides the necessary happens-before for readers; fields stay
     * non-final to keep {@code loadUserAuth} simple.
     */
    private static class UserAuthCache {
        boolean isAdmin;
        Set<String> grantedPermissions;
        boolean hasChannelRestrictions;
        Set<String> allowedChannelIds;
    }
}
