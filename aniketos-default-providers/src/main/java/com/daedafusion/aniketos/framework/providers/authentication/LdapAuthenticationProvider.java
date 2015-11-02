package com.daedafusion.aniketos.framework.providers.authentication;

import com.daedafusion.aniketos.framework.providers.identity.LdapIdentityBackend;
import com.daedafusion.aniketos.framework.providers.identity.LdapIdentityBackendException;
import com.daedafusion.aniketos.framework.providers.identity.LdapIdentityBackend.BindResult;
import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Principal;
import com.daedafusion.security.authentication.Role;
import com.daedafusion.security.authentication.SharedAuthenticationState;
import com.daedafusion.security.authentication.impl.DefaultAssociationPrincipal;
import com.daedafusion.security.authentication.impl.DefaultAuthenticatedPrincipal;
import com.daedafusion.security.authentication.impl.DefaultRole;
import com.daedafusion.security.authentication.providers.AuthenticationProvider;
import com.daedafusion.security.common.Callback;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.common.impl.DefaultCallback;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 7/19/14.
 */
public class LdapAuthenticationProvider extends AbstractProvider implements AuthenticationProvider
{

    private static final Logger log = Logger.getLogger(LdapAuthenticationProvider.class);

    private LdapIdentityBackend ldapBackEnd;
    private Map<UUID, SharedAuthenticationState> sessions;
    private KeyPair keyPair;

    public LdapAuthenticationProvider()
    {
        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {
                log.info("provider init");
                sessions = new ConcurrentHashMap<UUID, SharedAuthenticationState>();
                ldapBackEnd = LdapIdentityBackend.getInstance();
                try
                {
                    keyPair = KeyGenUtil.generateKeyPair();
                }
                catch (KeyMaterialException e)
                {
                    log.error("", e);
                }
            }

            @Override
            public void start()
            {
                log.info("provider start");
            }

            @Override
            public void stop()
            {
                log.info("provider stop");
            }

            @Override
            public void teardown()
            {
                log.info("provider teardown");
            }
        });
    }

    @Override
    public UUID initialize(SharedAuthenticationState state)
    {
        if (state == null)
            throw new RuntimeException("Shared Authentication State not provided");

        // Add a map entry for the UUID so we can track the domain and username
        // associated with the UUID
        UUID sessionId = UUID.randomUUID();
        sessions.put(sessionId, state);

        return sessionId;
    }

    @Override
    public boolean login(UUID id, CallbackHandler handler) throws AccountLockedException, PasswordResetRequiredException, PasswordQualityException
    {
        SharedAuthenticationState state;

        // Ensure there is a handler with which to handle callbacks
        if (handler == null)
            throw new RuntimeException("Handler not provided");

        // retrieve the authentication info used for this instance
        if (id == null || (state = sessions.get(id)) == null)
            return false;        // the UUID provided was either null or not found

        // Collect credentials used for authentication
        if (!collectCredentials(handler, state))
            return false;

        // attempt to authenticate using the credentials with the LDAP server
        BindResult result;
        Identity userIdentity;

        try
        {
            if (state.getState(Callback.OLD_PASSWORD) == null)
            {
                result = ldapBackEnd.bind(state.getState(Callback.USERNAME).toString(),
                        state.getState(Callback.DOMAIN).toString(),
                        state.getState(Callback.PASSWORD).toString());
            }
            else
            {
                result = ldapBackEnd.bindAndReset(state.getState(Callback.USERNAME).toString(),
                        state.getState(Callback.DOMAIN).toString(),
                        state.getState(Callback.OLD_PASSWORD).toString(),
                        state.getState(Callback.PASSWORD).toString());
            }

            switch (result)
            {
                case INVALID_CREDENTIALS:
                    return false;

                case ACCOUNT_LOCKED:
                    throw new AccountLockedException();

                case CHANGE_AFTER_RESET:
                case PASSWORD_EXPIRED:
                    throw new PasswordResetRequiredException();

                case INSUFFICIENT_PASSWORD_QUALITY:
                case PASSWORD_TOO_LONG:
                case PASSWORD_TOO_SHORT:
                case PASSWORD_IN_HISTORY:
                case PASSWORD_TOO_YOUNG:
                    throw new PasswordQualityException();

                case SUCCESS:
                    // retrieve an Identity from the LDAP directory
                    userIdentity = ldapBackEnd.getIdentity(state.getState(Callback.USERNAME).toString(),
                            state.getState(Callback.DOMAIN).toString());

                    if (userIdentity == null)
                    {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
        }
        catch (LdapIdentityBackendException e)
        {
            log.error(e);
            return false;
        }

        // Convert the Identity into the necessary attributes and save them as shared state
        Map<String, Set<String>> attributes = buildIdentityAttributes(userIdentity);
        state.addState("identityAttributes", attributes);

        // Convert the domain into the necessary attributes and save them as shared state
        Map<String, Set<String>> domainAttributes = buildOrgAttributes(userIdentity.getDomain());
        state.addState("orgAttributes", domainAttributes);

        // Add the entitled capabilities as shared state so that they can be added
        state.addState("entitledCapabilities", userIdentity.getAttributes());

        // set the Authentication state to true
        state.addState("AuthenSucceeded", true);

        return true;
    }

    @Override
    public AuthenticatedPrincipal commit(UUID id)
    {
        SharedAuthenticationState state;


        // retrieve the authentication info used for this instance
        if (id == null || (state = sessions.get(id)) == null)
            return null;        // the UUID provided was either null or not found

        // Should NOT have gotten here as authentication would have failed
        // and commit should NOT have been called.
        Object obj;
        if ((obj = state.getState("AuthenSucceeded")) == null || !((boolean) obj))
            return null;

        // Generate an instance Id for the AuthenticatedPrincipal
        UUID instanceId = UUID.randomUUID();

        // retrieve the identity attributes from shared authentication state
        Map<String, Set<String>> attributes = (Map<String, Set<String>>) state.getState("identityAttributes");

        // Compute the signature
        String signature = null;
        PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);
        if (attributes != null)
        {
            // compute the signature
            signature = computeSignature(crypto, instanceId, Principal.Type.ACCOUNT, attributes);
        }

        // Create the AuthenticatedPrincipal that represents authenticated identity
        AuthenticatedPrincipal ap = new DefaultAuthenticatedPrincipal(instanceId,
                Principal.Type.ACCOUNT,
                attributes,
                signature);

        // Map the domain to an Associated Principal for organization
        Map<String, Set<String>> orgAttributes = (Map<String, Set<String>>) state.getState("orgAttributes");
        if (orgAttributes != null)
        {
            Principal org = buildAssociationPrincipal(null, Principal.Type.ORGANIZATION, orgAttributes, crypto);
            if (org != null)
                ap.addAssociation(org);
        }

        // Add the associations such as organizations, groups, roles
        Map<String, Set<String>> capabilities = (Map<String, Set<String>>) state.getState("entitledCapabilities");
        if (capabilities != null)
        {
            for (String capabilityName : capabilities.get(Identity.ATTR_CAPABILITIES))
            {
                // Map each of the entitled capabilities as a role
                Role capability = buildRole(capabilityName, Role.RoleType.STATIC, null, crypto);

                // add the capability as an association
                ap.addAssociation(capability);
            }
        }

        // Set that the commit succeeded
        state.addState("CommitSucceeded", true);

        // Save the AuthenticatedPrincipal should be need to log it off
        // as a result of a abort from another provider
        state.addState("AuthenticatedPrincipal", ap);

        // remove the session
        sessions.remove(id);

        // return the created AuthenticatedPrincipal
        return ap;
    }

    @Override
    public void logoff(AuthenticatedPrincipal principal)
    {
        // since ldap is not managing the session there is nothing to do
        return;
    }

    @Override
    public void abort(UUID id)
    {
        SharedAuthenticationState state;

        // retrieve the authentication info used for this instance
        if (id == null || (state = sessions.get(id)) == null)
            return;        // the UUID provided was either null or not found

        // remove the state entry from the list of active sessions
        sessions.remove(id);

        // authentication failed but the framework is requesting an abort
        Object obj;
        if ((obj = state.getState("AuthenSucceeded")) == null || !((boolean) obj))
            return;
        else
        {
            if ((obj = state.getState("CommitSucceed")) != null && ((boolean) obj))
            {
                // overall authentication succeeded and commit succeeded,
                // but someone else's commit failed
                AuthenticatedPrincipal ap = (AuthenticatedPrincipal) state.getState("AuthenticatedPrincipal");
                logoff(ap);
            }
        }
    }

    @Override
    public boolean verify(AuthenticatedPrincipal principal)
    {
        try
        {
            byte[] sig = Hex.decodeHex(principal.getSignature().toCharArray());

            PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            baos.write(principal.getInstanceId().toString().getBytes());
            baos.write(principal.getType().toString().getBytes());

            SortedSet<String> sortedKeys = new TreeSet<>(principal.getAttributeNames());

            for (String key : sortedKeys)
            {
                baos.write(key.getBytes());
                // for each in set
                //baos.write(principal.getAttributes(key).getBytes());
            }

            return crypto.verify(sig, baos.toByteArray());
        }
        catch (DecoderException | CryptoException | IOException e)
        {
            log.error("", e);
        }

        return false;
    }

    @Override
    public String getAuthority()
    {
        return LdapAuthenticationProvider.class.getName();
    }


    private String computeSignature(PublicCrypto crypto, UUID instanceId, Principal.Type type, Map<String, Set<String>> attributes)
    {
        String signature = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try
        {
            baos.write(instanceId.toString().getBytes());
            baos.write(type.toString().getBytes());

            TreeSet<String> sortedKeys = new TreeSet<>(attributes.keySet());

            for (String key : sortedKeys)
            {
                baos.write(key.getBytes());
            }

            byte[] sig = crypto.sign(baos.toByteArray());

            signature = Hex.encodeHexString(sig);
        }
        catch (IOException | CryptoException e)
        {
            log.error("", e);
        }

        return signature;
    }


    private boolean collectCredentials(CallbackHandler handler, SharedAuthenticationState state)
    {
        // Create necessary callbacks to inquire for the authentication credentials
        List<DefaultCallback> callbacks = new ArrayList<>();
        callbacks.add(new DefaultCallback(Callback.DOMAIN));
        callbacks.add(new DefaultCallback(Callback.USERNAME));
        callbacks.add(new DefaultCallback(Callback.PASSWORD));
        callbacks.add(new DefaultCallback(Callback.OLD_PASSWORD));

        // Obtain the credentials from the caller
        try
        {
            handler.handle(callbacks.toArray(new DefaultCallback[callbacks.size()]));

            boolean parseUsername = true;

            // only add to shared state if the callback has a value
            for (DefaultCallback cb : callbacks)
            {
                if (cb.getName().equals(Callback.DOMAIN) && cb.getValue() != null)
                {
                    state.addState(Callback.DOMAIN, cb.getValue());
                    parseUsername = false;
                }
                else if (cb.getName().equals(Callback.USERNAME) && cb.getValue() != null)
                {
                    if (!parseUsername)
                        state.addState(Callback.USERNAME, cb.getValue());
                    else
                    {
                        String[] tokens = cb.getValue().split("@");
                        state.addState(Callback.USERNAME, tokens[0]);
                        state.addState(Callback.DOMAIN, tokens[1]);
                    }
                }
                else if (cb.getName().equals(Callback.OLD_PASSWORD) && cb.getValue() != null)
                {
                    state.addState(Callback.OLD_PASSWORD, cb.getValue());
                }
                else if (cb.getName().equals(Callback.PASSWORD) && cb.getValue() != null)
                {
                    state.addState(Callback.PASSWORD, cb.getValue());
                }
            }
        }
        catch (Exception e)
        {
            log.error(e);
            return false;
        }

        return true;
    }


    private Role buildRole(String roleName, Role.RoleType roleType, Map<String, Set<String>> attributes, PublicCrypto crypto)
    {
        // generate an instance Id for the role
        UUID roleId = UUID.randomUUID();
        Map<String, Set<String>> roleAttributes;

        // build up the attributes if not specified
        if ((roleName != null) && (attributes == null))
            roleAttributes = buildRoleAttributes(roleName);
        else
            roleAttributes = attributes;

        // compute the signature
        String signature = computeSignature(crypto, roleId, Principal.Type.ROLE, roleAttributes);

        // Create the corresponding role that represents the capability

        return new DefaultRole(roleId,
                Principal.Type.ROLE,
                roleAttributes,
                roleType,
                signature);
    }


    private Principal buildAssociationPrincipal(String identity, Principal.Type type, Map<String, Set<String>> attributes, PublicCrypto crypto)
    {
        Map<String, Set<String>> assocAttributes;

        // generate an instance Id for the association principal
        UUID instanceId = UUID.randomUUID();

        // build up the attributes if not specified
        if ((identity != null) && (attributes == null))
            assocAttributes = buildAssocPrincipalAttributes(identity);
        else
            assocAttributes = attributes;

        // compute the signature
        String signature = computeSignature(crypto, instanceId, type, attributes);

        // Create the corresponding role that represents the capability

        return new DefaultAssociationPrincipal(instanceId,
                type,
                assocAttributes,
                signature);
    }


    private Map<String, Set<String>> buildIdentityAttributes(Identity userIdentity)
    {

        // Convert the Identity into the necessary attributes
        Map<String, Set<String>> attributes = new HashMap<>();

        // Use the current time in milliseconds since epoch as the creation timestamp
        String creationTime = Long.toString(System.currentTimeMillis());
        attributes.put(Principal.PRINCIPAL_CREATION_TIME,
                Collections.singleton(creationTime));

        //  Use 1.3.6.1.4.1.43975.3.1.1.1 (LDAP Authentication Provider) as the PRINCIPAL_AUTHORITY
        attributes.put(Principal.PRINCIPAL_AUTHORITY,
                Collections.singleton(LdapAuthenticationProvider.class.getName()));

        // use domain into which the authentication occurred as the PRINCIPAL_DOMAIN
        attributes.put(Principal.PRINCIPAL_DOMAIN,
                Collections.singleton(userIdentity.getDomain()));

        // use the LDAP uid for the user as the PRINCIPAL_NAME
        attributes.put(Principal.PRINCIPAL_NAME,
                Collections.singleton(userIdentity.getUsername()));

        // use username@domain as the PRINCIPAL_DOMAIN_QUALIFIED_NAME
        attributes.put(Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME,
                Collections.singleton(userIdentity.getUsername() + "@" + userIdentity.getDomain()));

        //Use the LDAP fully qualified DN of the user for the PRINCIPAL_IDENTIFIER
        attributes.put(Principal.PRINCIPAL_IDENTIFIER,
                Collections.singleton(userIdentity.getIdentifier()));

        return attributes;
    }


    private Map<String, Set<String>> buildRoleAttributes(String roleName)
    {
        // Convert the Role into the necessary attributes
        Map<String, Set<String>> attributes = new HashMap<>();

        // Use the current time in milliseconds since epoch as the creation timestamp
        String creationTime = Long.toString(System.currentTimeMillis());
        attributes.put(Principal.PRINCIPAL_CREATION_TIME,
                Collections.singleton(creationTime));

        //  Use 1.3.6.1.4.1.43975.3.1.1.1 (LDAP Authentication Provider) as the PRINCIPAL_AUTHORITY
        attributes.put(Principal.PRINCIPAL_AUTHORITY,
                Collections.singleton(LdapAuthenticationProvider.class.getName()));

        // use the role name for the user as the PRINCIPAL_NAME
        attributes.put(Principal.PRINCIPAL_NAME,
                Collections.singleton(roleName));

        return attributes;
    }


    private Map<String, Set<String>> buildOrgAttributes(String orgName)
    {
        // Convert the organization into the necessary attributes
        Map<String, Set<String>> attributes = new HashMap<>();

        // Use the current time in milliseconds since epoch as the creation timestamp
        String creationTime = Long.toString(System.currentTimeMillis());
        attributes.put(Principal.PRINCIPAL_CREATION_TIME,
                Collections.singleton(creationTime));

        //  Use 1.3.6.1.4.1.43975.3.1.1.1 (LDAP Authentication Provider) as the PRINCIPAL_AUTHORITY
        attributes.put(Principal.PRINCIPAL_AUTHORITY,
                Collections.singleton(LdapAuthenticationProvider.class.getName()));

        // use the role name for the user as the PRINCIPAL_NAME
        attributes.put(Principal.PRINCIPAL_NAME,
                Collections.singleton(orgName));

        return attributes;
    }


    private Map<String, Set<String>> buildAssocPrincipalAttributes(String identity)
    {
        // Convert the organization into the necessary attributes
        Map<String, Set<String>> attributes = new HashMap<>();

        // Use the current time in milliseconds since epoch as the creation timestamp
        String creationTime = Long.toString(System.currentTimeMillis());
        attributes.put(Principal.PRINCIPAL_CREATION_TIME,
                Collections.singleton(creationTime));

        //  Use 1.3.6.1.4.1.43975.3.1.1.1 (LDAP Authentication Provider) as the PRINCIPAL_AUTHORITY
        attributes.put(Principal.PRINCIPAL_AUTHORITY,
                Collections.singleton(LdapAuthenticationProvider.class.getName()));

        // use the identity as the PRINCIPAL_NAME
        attributes.put(Principal.PRINCIPAL_NAME,
                Collections.singleton(identity));

        return attributes;
    }
}
