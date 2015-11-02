package com.daedafusion.aniketos.framework.providers.identity;


import com.daedafusion.configuration.*;
import com.daedafusion.security.common.*;
import com.daedafusion.security.common.PasswordPolicy.PasswordQualityCheck;
import com.daedafusion.security.common.PasswordPolicy.TOTP;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.ldap.client.api.DefaultLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.PoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.template.EntryMapper;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;
import org.apache.directory.ldap.client.template.PasswordWarning;
import org.apache.directory.ldap.client.template.RequestBuilder;
import org.apache.directory.ldap.client.template.exception.*;
import org.apache.log4j.Logger;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;


public final class LdapIdentityBackend
{
    private static final Logger log = Logger.getLogger(LdapIdentityBackend.class);

    private static LdapIdentityBackend ourInstance = new LdapIdentityBackend();

    public enum BindResult
    {
        SUCCESS,                            // Bind to authenticate succeed
        FAILURE,                            // General failure
        INVALID_CREDENTIALS,                // Credentials supplied were invalid
        ACCOUNT_LOCKED,                    // Account is locked
        CHANGE_AFTER_RESET,                // Password must be changed as it was reset by administrator
        PASSWORD_EXPIRED,                // Password has expired and must be reset
        PASSWORD_IN_HISTORY,                // Password can't be reused as its already exists in password history
        MUST_SUPPLY_OLD_PASSWORD,            // Password modification requires previous password to be supplied
        INSUFFICIENT_PASSWORD_QUALITY,    // Password doesn't meet password quality guidelines
        PASSWORD_TOO_SHORT,                // Password does not meet minimum password length guidelines
        PASSWORD_TOO_LONG,                // Password does not meet maximum password length guidelines
        PASSWORD_TOO_YOUNG                // Password modification occurring too quickly
    }


    private LdapConnectionTemplate ldapConnectionTemplate;
    private static Map<String, String> capabilityCache;

    private static String baseDN;

    private static final EntryMapper<Identity> identityEntryMapper = new EntryMapper<Identity>()
    {
        @Override
        public Identity map(Entry entry) throws LdapException
        {
            String identifier;
            Map<String, Set<String>> attributes = new HashMap<>();

            Identity identity = new Identity();
            Collection<Attribute> attrs = entry.getAttributes();

            // Use the entry DN as the identifier
            identity.setIdentifier(entry.getDn().toString());

            for (Attribute attr : attrs)
            {
                // get the identifier of the attribute
                identifier = attr.getId();

                // Skip attributes with types that are not human-readable
                // since jpegPhoto is based64 encoded, let it through
                if (!attr.isHumanReadable() && !identifier.equalsIgnoreCase("jpegPhoto"))
                    continue;

                // skip certain attributes with are uninteresting
                if (identifier.equalsIgnoreCase("objectClass") || identifier.equalsIgnoreCase("secretary") ||
                        identifier.equalsIgnoreCase("seeAlso") || identifier.equalsIgnoreCase("pwdPolicySubentry"))
                    continue;

                if (identifier.equalsIgnoreCase("uid") || identifier.equalsIgnoreCase("userid"))
                {
                    identity.setUsername(attr.get().toString());
                    continue;
                }
                else if (identifier.equalsIgnoreCase("o") || identifier.equalsIgnoreCase("organizationName"))
                {
                    identity.setDomain(attr.get().toString());
                    continue;
                }

                Iterator<Value<?>> itr = attr.iterator();
                Set<String> attrValues = new HashSet<>();
                while (itr.hasNext())
                {
                    // Convert LDAP timestamps to ISO 8601 format
                    if (identifier.equalsIgnoreCase("createTimestamp") ||
                            identifier.equalsIgnoreCase("pwdChangedTime") ||
                            identifier.equalsIgnoreCase("pwdAccountLockedTime") ||
                            identifier.equalsIgnoreCase("pwdFailureTime") ||
                            identifier.equalsIgnoreCase("pwdLastSuccess") ||
                            identifier.equalsIgnoreCase("pwdStartTime") ||
                            identifier.equalsIgnoreCase("pwdEndTime"))
                        attrValues.add(convertToISO8601(itr.next().getString()));

                        // Convert the DN representation of the Capability to its name form
                    else if (identifier.equalsIgnoreCase("entitledCapabilities"))
                        attrValues.add(capabilityCache.get(itr.next().getString()));
                    else
                        attrValues.add(itr.next().getString());
                }

                if (identifier.equalsIgnoreCase("cn") || identifier.equalsIgnoreCase("commonName"))
                    attributes.put(Identity.ATTR_FULLNAME, attrValues);
                else if (identifier.equalsIgnoreCase("sn") || identifier.equalsIgnoreCase("surName"))
                    attributes.put(Identity.ATTR_LASTNAME, attrValues);
                else if (identifier.equalsIgnoreCase("gn") || identifier.equalsIgnoreCase("givenName"))
                    attributes.put(Identity.ATTR_FIRSTNAME, attrValues);
                else if (identifier.equalsIgnoreCase("fax") || identifier.equalsIgnoreCase("facimileTelephoneNumber"))
                    attributes.put(Identity.ATTR_FAX, attrValues);
                else if (identifier.equalsIgnoreCase("homePhone") || identifier.equalsIgnoreCase("homeTelephoneNumber"))
                    attributes.put(Identity.ATTR_HOME_PHONE, attrValues);
                else if (identifier.equalsIgnoreCase("l") || identifier.equalsIgnoreCase("localityName"))
                    attributes.put(Identity.ATTR_LOCALITY, attrValues);
                else if (identifier.equalsIgnoreCase("mail") || identifier.equalsIgnoreCase("rfc822Mailbox"))
                    attributes.put(Identity.ATTR_MAIL, attrValues);
                else if (identifier.equalsIgnoreCase("mobile") || identifier.equalsIgnoreCase("mobileTelephoneNumber"))
                    attributes.put(Identity.ATTR_MOBILE_PHONE, attrValues);
                else if (identifier.equalsIgnoreCase("pager") || identifier.equalsIgnoreCase("pagerTelephoneNumber"))
                    attributes.put(Identity.ATTR_PAGER, attrValues);
                else if (identifier.equalsIgnoreCase("st") || identifier.equalsIgnoreCase("stateOrProvinceName"))
                    attributes.put(Identity.ATTR_STATE_PROVINCE, attrValues);
                else if (identifier.equalsIgnoreCase("street") || identifier.equalsIgnoreCase("streetAddress"))
                    attributes.put(Identity.ATTR_STREET, attrValues);
                else if (identifier.equalsIgnoreCase("authenticatorKey"))
                    attributes.put(Identity.ATTR_AUTHENTICATOR_KEY, attrValues);
                else if (identifier.equalsIgnoreCase("entitledCapabilities"))
                    attributes.put(Identity.ATTR_CAPABILITIES, attrValues);
                else if (identifier.equalsIgnoreCase("createTimestamp"))
                    attributes.put(Identity.ATTR_ACCNT_CREATION, attrValues);
                else if (identifier.equalsIgnoreCase("pwdChangedTime"))
                    attributes.put(Identity.ATTR_PWD_CHANGE, attrValues);
                else if (identifier.equalsIgnoreCase("pwdAccounLockedTime"))
                    attributes.put(Identity.ATTR_ACCNT_LOCK, attrValues);
                else if (identifier.equalsIgnoreCase("pwdFailureTime"))
                    attributes.put(Identity.ATTR_FAILURE_TIME, attrValues);
                else if (identifier.equalsIgnoreCase("pwdStartTime"))
                    attributes.put(Identity.ATTR_PWD_STARTTIME, attrValues);
                else if (identifier.equalsIgnoreCase("pwdEndTime"))
                    attributes.put(Identity.ATTR_PWD_ENDTIME, attrValues);
                else if (identifier.equalsIgnoreCase("pwdLastSuccess"))
                    attributes.put(Identity.ATTR_LAST_SUCCESS, attrValues);
                else if (identifier.equalsIgnoreCase("pwdReset"))
                    attributes.put(Identity.ATTR_PWD_RESET, attrValues);
                else if (identifier.equalsIgnoreCase("jpegPhoto"))
                    attributes.put(Identity.ATTR_JPEG_PHOTO, attrValues);
                else if (!attrValues.isEmpty())
                    attributes.put(identifier, attrValues);
            }

            // add the attributes to the identity
            identity.setAttributes(attributes);

            // return the populated identity
            return identity;
        }
    };

    private static final EntryMapper<Domain> domainEntryMapper = new EntryMapper<Domain>()
    {
        @Override
        public Domain map(Entry entry) throws LdapException
        {
            String identifier;
            Map<String, Set<String>> attributes = new HashMap<>();

            Domain domain = new Domain();
            Collection<Attribute> attrs = entry.getAttributes();

            for (Attribute attr : attrs)
            {
                // get the identifier of the attribute
                identifier = attr.getId();

                // Skip attributes with types that are not human-readable
                if (!attr.isHumanReadable())
                    continue;

                // skip certain attributes with are uninteresting
                if (identifier.equalsIgnoreCase("objectClass") || identifier.equalsIgnoreCase("seeAlso"))
                    continue;

                if (identifier.equalsIgnoreCase("o") || identifier.equalsIgnoreCase("organizationName"))
                {
                    domain.setDomainName(attr.get().toString());
                    continue;
                }
                else if (identifier.equalsIgnoreCase("description"))
                {
                    domain.setDescription(attr.get().getString());
                    continue;
                }

                Iterator<Value<?>> itr = attr.iterator();
                Set<String> attrValues = new HashSet<>();
                while (itr.hasNext())
                    attrValues.add(itr.next().getString());

                if (identifier.equalsIgnoreCase("fax") || identifier.equalsIgnoreCase("facimileTelephoneNumber"))
                    attributes.put(Domain.ATTR_FAX, attrValues);
                else if (identifier.equalsIgnoreCase("l") || identifier.equalsIgnoreCase("localityName"))
                    attributes.put(Domain.ATTR_LOCALITY, attrValues);
                else if (identifier.equalsIgnoreCase("st") || identifier.equalsIgnoreCase("stateOrProvinceName"))
                    attributes.put(Domain.ATTR_STATE_PROVINCE, attrValues);
                else if (identifier.equalsIgnoreCase("street") || identifier.equalsIgnoreCase("streetAddress"))
                    attributes.put(Domain.ATTR_STREET, attrValues);
                else if (!attrValues.isEmpty())
                    attributes.put(identifier, attrValues);
            }

            // add the attributes to the domain
            domain.setAttributes(attributes);

            // return the populated domain
            return domain;
        }
    };

    private static final EntryMapper<Capability> capabilityEntryMapper = new EntryMapper<Capability>()
    {
        @Override
        public Capability map(Entry entry) throws LdapException
        {
            String identifier;
            Map<String, Set<String>> attributes = new HashMap<>();

            Capability capability = new Capability();
            Collection<Attribute> attrs = entry.getAttributes();

            for (Attribute attr : attrs)
            {
                // get the identifier of the attribute
                identifier = attr.getId();

                // Skip attributes with types that are not human-readable
                if (!attr.isHumanReadable())
                    continue;

                // skip certain attributes with are uninteresting
                if (identifier.equalsIgnoreCase("objectClass") || identifier.equalsIgnoreCase("seeAlso"))
                    continue;

                if (identifier.equalsIgnoreCase("cn") || identifier.equalsIgnoreCase("commonName"))
                {
                    capability.setCapabilityName(attr.get().toString());
                    continue;
                }
                else if (identifier.equalsIgnoreCase(Capability.ATTR_DESCRIPTION))
                {
                    capability.setDescription(attr.get().getString());
                    continue;
                }

                Iterator<Value<?>> itr = attr.iterator();
                Set<String> attrValues = new HashSet<>();
                while (itr.hasNext())
                    attrValues.add(itr.next().getString());

                if (!attrValues.isEmpty())
                    attributes.put(identifier, attrValues);
            }

            // add the attributes to the capability
            capability.setAttributes(attributes);

            // return the populated capability
            return capability;
        }
    };

    private static final EntryMapper<PasswordPolicy> passwordPolicyEntryMapper = new EntryMapper<PasswordPolicy>()
    {
        @Override
        public PasswordPolicy map(Entry entry) throws LdapException
        {
            String identifier;
            Long lValue;
            Integer iValue;

            PasswordPolicy policy = new PasswordPolicy();
            Collection<Attribute> attrs = entry.getAttributes();

            for (Attribute attr : attrs)
            {
                // get the identifier of the attribute
                identifier = attr.getId();

                // Skip attributes with types that are not human-readable
                if (!attr.isHumanReadable())
                    continue;

                //  Skip attributes that are uninteresting
                if (identifier.equalsIgnoreCase("objectClass") ||
                        identifier.equalsIgnoreCase("ads-pwdId") ||
                        identifier.equalsIgnoreCase("ads_pwdAttribute") ||
                        identifier.equalsIgnoreCase("ads-pwdValidator"))
                    continue;

                if (identifier.equalsIgnoreCase("ads-enabled"))
                {
                    if (!Boolean.valueOf(attr.get().toString()))
                        policy.setPolicyEnabled(false);
                    else
                        policy.setPolicyEnabled(true);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMinAge"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setMinAge(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMaxAge"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setMaxAge(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdCheckQuality"))
                {
                    iValue = Integer.valueOf(attr.get().toString());
                    switch (iValue)
                    {
                        case 0:
                            policy.setQualityCheckLevel(PasswordQualityCheck.DISABLED);
                            break;
                        case 1:
                            policy.setQualityCheckLevel(PasswordQualityCheck.RELAXED);
                            break;
                        case 2:
                            policy.setQualityCheckLevel(PasswordQualityCheck.STRICT);
                            break;
                    }
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMinLength"))
                {
                    iValue = Integer.valueOf(attr.get().toString());
                    policy.setMinLength(iValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMaxLength"))
                {
                    iValue = Integer.valueOf(attr.get().toString());
                    policy.setMaxLength(iValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdExpireWarning"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setExpireWarning(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdGraceAuthNLimit"))
                {
                    iValue = Integer.valueOf(attr.get().toString());
                    policy.setGraceAuthnLimit(iValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdGraceExpiry"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setGraceExpiry(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMustChange"))
                {
                    if (!Boolean.valueOf(attr.get().toString()))
                        policy.setMustChange(false);
                    else
                        policy.setMustChange(true);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdAllowUserChange"))
                {
                    if (!Boolean.valueOf(attr.get().toString()))
                        policy.setAllowUserChange(false);
                    else
                        policy.setAllowUserChange(true);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdSafeModify"))
                {
                    if (!Boolean.valueOf(attr.get().toString()))
                        policy.setSafeModify(false);
                    else
                        policy.setSafeModify(true);
                }
            }

            return policy;
        }
    };


    private static final EntryMapper<LockoutPolicy> lockoutPolicyEntryMapper = new EntryMapper<LockoutPolicy>()
    {
        @Override
        public LockoutPolicy map(Entry entry) throws LdapException
        {
            String identifier;
            Long lValue;
            Integer iValue;

            LockoutPolicy policy = new LockoutPolicy();
            Collection<Attribute> attrs = entry.getAttributes();

            for (Attribute attr : attrs)
            {
                // get the identifier of the attribute
                identifier = attr.getId();

                // Skip attributes with types that are not human-readable
                if (!attr.isHumanReadable())
                    continue;

                //  Skip attributes that are uninteresting
                if (identifier.equalsIgnoreCase("objectClass") ||
                        identifier.equalsIgnoreCase("ads-pwdId") ||
                        identifier.equalsIgnoreCase("ads_pwdAttribute") ||
                        identifier.equalsIgnoreCase("ads-pwdValidator"))
                    continue;

                if (identifier.equalsIgnoreCase("ads-pwdLockout"))
                {
                    if (!Boolean.valueOf(attr.get().toString()))
                        policy.setPolicyEnabled(false);
                    else
                        policy.setPolicyEnabled(true);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdInHistory"))
                {
                    iValue = Integer.valueOf(attr.get().toString());
                    policy.setPasswordsInHistory(iValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdLockoutDuration"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setLockoutDuration(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMaxFailure"))
                {
                    iValue = Integer.valueOf(attr.get().toString());
                    policy.setMaxAttempts(iValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdFailureCountInterval"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setFailureCountInterval(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMinDelay"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setMinDelay(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMaxDelay"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setMaxDelay(lValue);
                }
                else if (identifier.equalsIgnoreCase("ads-pwdMaxIdle"))
                {
                    lValue = Long.valueOf(attr.get().toString());
                    policy.setMaxIdle(lValue);
                }
            }

            return policy;
        }
    };

    /**
     * convertToISO8601 -	Converts an LDAP timestamp in string form to
     * ISO 8601 string format
     *
     * @param timestamp
     * @return string
     */
    private static String convertToISO8601(String timestamp)
    {
        Date date;
        String isoTimestamp;

        try
        {
            TimeZone tz = TimeZone.getTimeZone("UTC");
            DateFormat df = new SimpleDateFormat("yyyyMMddHHmmss.SSSX");
            df.setTimeZone(tz);
            date = df.parse(timestamp);

            DateFormat df1 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            df1.setTimeZone(tz);
            isoTimestamp = df1.format(date);

        }
        catch (ParseException e)
        {
            log.error("", e);
            return null;
        }

        return isoTimestamp;
    }


    private LdapIdentityBackend()
    {
        // Get the default values from the LDAP Connection Config
        LdapConnectionConfig config = new LdapConnectionConfig();
        String defLdapHost = config.getDefaultLdapHost();
        int defLdapPort = config.getDefaultLdapsPort();
        long defTimeout = config.getDefaultTimeout();

        // Query configuration to get environment specific settings
        String ldapHost = Configuration.getInstance().getString("ldapHost", defLdapHost);
        int ldapPort = Integer.parseInt(Configuration.getInstance().getString("ldapPort", "" + defLdapPort));
        String ldapCredName = Configuration.getInstance().getString("ldapCredName", "admin");
        String ldapCredentials = Configuration.getInstance().getString("ldapCredentials", "secret");
        long ldapTimeout = Long.parseLong(Configuration.getInstance().getString("ldapTimeout", "" + defTimeout));

        baseDN = Configuration.getInstance().getString("ldapBaseDN", "dc=daedafusion,dc=com");

        // Set the connection configuration parameters
        config.setLdapHost(ldapHost);
        config.setLdapPort(ldapPort);
        config.setName(ldapCredName);
        config.setCredentials(ldapCredentials);

        // Create the connection factory - use the default implementation
        DefaultLdapConnectionFactory factory = new DefaultLdapConnectionFactory(config);
        factory.setTimeOut(ldapTimeout);

        // Configure the connection pool
        GenericObjectPool.Config poolConfig = new GenericObjectPool.Config();
        poolConfig.lifo = true;
        poolConfig.maxActive = 8;
        poolConfig.maxIdle = 8;
        poolConfig.maxWait = -1L;
        poolConfig.minEvictableIdleTimeMillis = 1000L * 60L * 30L;
        poolConfig.minIdle = 0;
        poolConfig.numTestsPerEvictionRun = 3;
        poolConfig.softMinEvictableIdleTimeMillis = -1L;
        poolConfig.testOnBorrow = false;
        poolConfig.testOnReturn = false;
        poolConfig.testWhileIdle = false;
        poolConfig.timeBetweenEvictionRunsMillis = -1L;
        poolConfig.whenExhaustedAction = GenericObjectPool.WHEN_EXHAUSTED_BLOCK;

        ldapConnectionTemplate =
                new LdapConnectionTemplate(
                        new LdapConnectionPool(
                                new PoolableLdapConnectionFactory(factory), poolConfig));

        // Build a lookup table of capabilities and their DN
        try
        {
            List<String> capabilities = this.listCapabilities();
            capabilityCache = new HashMap<>();
            for (String capabilityName : capabilities)
                capabilityCache.put("cn=" + capabilityName + ",ou=capabilities," + baseDN, capabilityName);
        }
        catch (LdapIdentityBackendException e)
        {
            log.error("", e);
        }
    }

    /**
     * Retrieves an instance of the LdapIdentityBackend singleton
     *
     * @return LdapIdentityBackend
     */
    public static LdapIdentityBackend getInstance()
    {
        return ourInstance;
    }


    public void setup()
    {
        // TODO: Create partition and load LDIF containing schema extensions and initial config
    }


    /**
     * Authenticates a identity using the credentials specified
     *
     * @param username Name of the user
     * @param domain   Name of the domain which the user is a member
     * @param password Pass phrase or word used for authentication
     * @return BindResult    Represents the result of the authentication attempt
     * @throws LdapIdentityBackendException
     */
    public BindResult bind(String username, String domain, String password) throws LdapIdentityBackendException
    {
        try
        {
            // Attempt to authenticate using provided credentials
            PasswordWarning warning = ldapConnectionTemplate.authenticate(
                    ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                    password.toCharArray());
            if (warning != null && warning.isChangeAfterReset())
                return BindResult.CHANGE_AFTER_RESET;
        }
        catch (PasswordException pwdExcept)
        {

            // check to see if Password Policy error
            if (pwdExcept.getPasswordPolicyError() != null)
            {
                switch (pwdExcept.getPasswordPolicyError())
                {
                    case ACCOUNT_LOCKED:
                        return BindResult.ACCOUNT_LOCKED;

                    case CHANGE_AFTER_RESET:
                        return BindResult.CHANGE_AFTER_RESET;

                    case PASSWORD_EXPIRED:
                        return BindResult.PASSWORD_EXPIRED;

                    default:
                        log.error("", pwdExcept);
                        return BindResult.FAILURE;
                }
            }
            else if (pwdExcept.getResultCode() == ResultCodeEnum.INVALID_CREDENTIALS)
                return BindResult.INVALID_CREDENTIALS;


            String msg = pwdExcept.getLocalizedMessage();
            if (msg == null && (msg = pwdExcept.getMessage()) == null)
                msg = "";

            log.error(msg, pwdExcept);
            throw new LdapIdentityBackendException(msg, pwdExcept);
        }

        return BindResult.SUCCESS;
    }


    /**
     * Authenticate the specified identity and change the password if the
     * authentication is successful.
     *
     * @param username
     * @param domain
     * @param oldPassword
     * @param newPassword
     * @return BindResult
     * @throws LdapIdentityBackendException
     */
    public BindResult bindAndReset(String username, String domain, String oldPassword, String newPassword) throws LdapIdentityBackendException
    {
        try
        {
            ldapConnectionTemplate.modifyPassword(
                    ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                    oldPassword.toCharArray(),
                    newPassword.toCharArray());
        }
        catch (PasswordException pwdExcept)
        {
            // check to see if Password Policy error
            if (pwdExcept.getPasswordPolicyError() != null)
            {
                switch (pwdExcept.getPasswordPolicyError())
                {
                    case ACCOUNT_LOCKED:
                        return BindResult.ACCOUNT_LOCKED;

                    case CHANGE_AFTER_RESET:
                        return BindResult.CHANGE_AFTER_RESET;

                    case PASSWORD_EXPIRED:
                        return BindResult.PASSWORD_EXPIRED;

                    case INSUFFICIENT_PASSWORD_QUALITY:
                        return BindResult.INSUFFICIENT_PASSWORD_QUALITY;

                    case PASSWORD_IN_HISTORY:
                        return BindResult.PASSWORD_IN_HISTORY;

                    case PASSWORD_TOO_SHORT:
                        return BindResult.PASSWORD_TOO_SHORT;

                    case PASSWORD_TOO_YOUNG:
                        return BindResult.PASSWORD_TOO_YOUNG;

                    case MUST_SUPPLY_OLD_PASSWORD:
                        return BindResult.MUST_SUPPLY_OLD_PASSWORD;

                    default:
                        log.error("", pwdExcept);
                        return BindResult.FAILURE;
                }
            }
            else if (pwdExcept.getResultCode() == ResultCodeEnum.INVALID_CREDENTIALS)
            {
                return BindResult.INVALID_CREDENTIALS;
            }


            String msg = pwdExcept.getLocalizedMessage();
            if (msg == null && (msg = pwdExcept.getMessage()) == null)
                msg = "";

            log.error(msg, pwdExcept);
            throw new LdapIdentityBackendException(msg, pwdExcept);
        }

        return BindResult.SUCCESS;
    }


    /**
     * Checks to determine if the password for a specified user has expired
     *
     * @param username the name of the user
     * @param domain   the domain in which the user is a member
     * @throws LdapIdentityBackendException
     * @return True is the password has expired, else false
     */
    public boolean isPasswordExpired(String username, String domain) throws LdapIdentityBackendException
    {
        // Get the domain-level password policy, else get the global password policy
        PasswordPolicy policy = getPasswordPolicy(domain);
        if (policy == null)
            policy = getPasswordPolicy(null);

        // Lookup the necessary attributes on the specified identity
        Map<String, String> pwdValues = ldapConnectionTemplate.lookup(
                ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                new String[]{"pwdChangedTime", "pwdMustChange", "pwdReset"},        //attribute list
                new EntryMapper<Map<String, String>>()
                {
                    @Override
                    public Map<String, String> map(Entry entry) throws LdapException
                    {
                        Map<String, String> pwdAttrs = new HashMap<>();
                        if (entry.get("pwdChangedTime") != null)
                            pwdAttrs.put("pwdChangedTime", entry.get("pwdChangedTime").getString());
                        if (entry.get("pwdMustChange") != null)
                            pwdAttrs.put("pwdMustChange", entry.get("pwdMustChange").getString());
                        if (entry.get("pwdReset") != null)
                            pwdAttrs.put("pwdReset", entry.get("pwdReset").getString());
                        return pwdAttrs;
                    }
                }
        );

        if (pwdValues != null)
        {
            // If the account had both pwdMustChange and PwdReset attributes
            // if should be considered as manually expired
            if (pwdValues.containsKey("pwdMustChange") && pwdValues.containsKey("pwdReset"))
                return true;

            if (pwdValues.containsKey("pwdChangedTime"))
            {
                Date pwdChangedTime;

                try
                {
                    TimeZone tz = TimeZone.getTimeZone("UTC");
                    DateFormat df = new SimpleDateFormat("yyyyMMddHHmmss.SSSX");
                    df.setTimeZone(tz);
                    pwdChangedTime = df.parse(pwdValues.get("pwdChangedTime"));
                }
                catch (Exception e)
                {
                    log.error("", e);
                    return false;
                }

                // Password is expired is current time - time of last change > max password age
                if (((System.currentTimeMillis() - pwdChangedTime.getTime()) / 1000) > policy.getMaxAge())
                    return true;
            }
        }

        return false;
    }


    /**
     * Sets the password for a specified user in a domain as expired
     *
     * @param username
     * @param domain
     * @throws LdapIdentityBackendException
     */
    public void expirePassword(String username, String domain) throws LdapIdentityBackendException
    {
        // Add the pwdMustChange and pwdReset attribute to force the user to change their password
        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        request.replace("pwdMustChange", "TRUE");
                        request.replace("pwdReset", "TRUE");
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Set the value of the userPassword attribute for the LDAP entity representing
     * the corresponding identity and marks the account so that the user will be
     * force to change the password upon successful authentication
     *
     * @param username
     * @param domain
     * @param password
     * @return BindResult
     * @throws LdapIdentityBackendException
     */
    public BindResult setIdentityPassword(String username, String domain, String password) throws LdapIdentityBackendException
    {
        try
        {
            ldapConnectionTemplate.modifyPassword(
                    ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                    null,
                    password.toCharArray(),
                    true);
        }
        catch (PasswordException pwdExcept)
        {
            // Check to see if its a password policy error
            if (pwdExcept.getPasswordPolicyError() != null)
            {
                switch (pwdExcept.getPasswordPolicyError())
                {
                    case ACCOUNT_LOCKED:
                        return BindResult.ACCOUNT_LOCKED;

                    case CHANGE_AFTER_RESET:
                        return BindResult.CHANGE_AFTER_RESET;

                    case PASSWORD_EXPIRED:
                        return BindResult.PASSWORD_EXPIRED;

                    case INSUFFICIENT_PASSWORD_QUALITY:
                        return BindResult.INSUFFICIENT_PASSWORD_QUALITY;

                    case PASSWORD_IN_HISTORY:
                        return BindResult.PASSWORD_IN_HISTORY;

                    case PASSWORD_TOO_SHORT:
                        return BindResult.PASSWORD_TOO_SHORT;

                    case PASSWORD_TOO_YOUNG:
                        return BindResult.PASSWORD_TOO_YOUNG;

                    case MUST_SUPPLY_OLD_PASSWORD:
                        return BindResult.MUST_SUPPLY_OLD_PASSWORD;

                    default:
                        log.error("", pwdExcept);
                        return BindResult.FAILURE;
                }
            }
            else if (pwdExcept.getResultCode() == ResultCodeEnum.INVALID_CREDENTIALS)
            {
                return BindResult.INVALID_CREDENTIALS;
            }

            String msg = pwdExcept.getLocalizedMessage();
            if (msg == null && (msg = pwdExcept.getMessage()) == null)
                msg = "";

            log.error(msg, pwdExcept);
            throw new LdapIdentityBackendException(msg, pwdExcept);
        }

        // Add the pwdMustChange and pwdReset attribute to force the user to change their password
        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        request.replace("pwdMustChange", "TRUE");
                        request.replace("pwdReset", "TRUE");
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        return BindResult.SUCCESS;
    }


    /**
     * Mark the LDAP entity representing this identity as disabled to prevent use
     *
     * @param username
     * @param domain
     * @throws LdapIdentityBackendException
     */
    public void disableIdentity(String username, String domain) throws LdapIdentityBackendException
    {
        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        request.add("pwdAccountLockedTime", "000001010000Z");
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Mark the LDAP entity representing this identity as enabled to allow use
     *
     * @param username
     * @param domain
     * @throws LdapIdentityBackendException
     */
    public void enableIdentity(String username, String domain) throws LdapIdentityBackendException
    {
        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        // Replace attribute with no value results in attribute being deleted
                        request.replace("pwdAccountLockedTime");
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Returns a list of Identity objects for all identities, regardless of domain
     *
     * @return List<Identity>
     * @throws LdapIdentityBackendException
     */
    public List<Identity> getAllIdentities() throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search(baseDN,
                    "(objectclass=inetOrgPerson)",
                    SearchScope.SUBTREE,
                    identityEntryMapper);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }

    }


    /**
     * Retrieves a list of names for all identities defined
     *
     * @return List<String>
     * @throws LdapIdentityBackendException
     */
    public List<String> listAllIdentities() throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search(baseDN,
                    "(objectClass=inetOrgPerson)", SearchScope.ONELEVEL,
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.get("uid").getString();
                        }
                    });
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }


    /**
     * Returns a list of Identity objects for all identities within the domain specified
     *
     * @param domain
     * @return List<Identity>
     * @throws LdapIdentityBackendException
     */
    public List<Identity> getIdentitiesForDomain(String domain) throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search("ou=users,o=" + domain + "," + baseDN,
                    "(objectclass=inetOrgPerson)",
                    SearchScope.ONELEVEL,
                    identityEntryMapper);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }

    /**
     * Returns an Identity object containing details about the specified identity within the specified domain
     *
     * @param username
     * @param domain
     * @return Identity
     * @throws LdapIdentityBackendException
     */
    public Identity getIdentity(String username, String domain) throws LdapIdentityBackendException
    {
        String[] attrs = new String[]{"*",                    // All user attributes
                "createTimestamp",        // time account was created
                "pwdChangedTime",        // time password was last changed
                "pwdAccountLockedTime",    // time account was locked
                "pwdFailureTime",        // time(s) of consecutive authentication failures
                "pwdStartTime",            // time a password becomes valid for authentication
                "pwdEndTime",            // time a password becomes invalid for authentication
                "pwdLastSuccess",        // time of last success authentication
                "pwdReset"};            // indication of password reset

        try
        {
            return ldapConnectionTemplate.lookup(
                    ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN),
                    attrs,
                    identityEntryMapper);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }

    /**
     * Creates an identity entry in LDAP for the specified Identity and assigns
     * a Password and Lockout policy under which the account will be governed
     *
     * @param identity
     * @return Identity
     * @throws LdapIdentityBackendException
     */
    public Identity createIdentity(final Identity identity) throws LdapIdentityBackendException
    {
        AddResponse response = ldapConnectionTemplate.add(
                ldapConnectionTemplate.newDn("uid=" + identity.getUsername() + ",ou=users,o=" + identity.getDomain() + "," + baseDN),
                new RequestBuilder<AddRequest>()
                {
                    @Override
                    public void buildRequest(AddRequest request) throws LdapException
                    {
                        Entry entry = request.getEntry();
                        entry.add("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson", "argosUser");
                        entry.add("uid", identity.getUsername());
                        entry.add("o", identity.getDomain());

                        Map<String, Set<String>> attributes = identity.getAttributes();
                        for (String key : attributes.keySet())
                        {
                            // Skip any special read-only attributes
                            if (key.equalsIgnoreCase("createTimestamp") ||
                                    key.equalsIgnoreCase("pwdChangedTime") ||
                                    key.equalsIgnoreCase("pwdAccountLockedTime") ||
                                    key.equalsIgnoreCase("pwdFailureTime") ||
                                    key.equalsIgnoreCase("pwdStartTime") ||
                                    key.equalsIgnoreCase("pwdEndTime") ||
                                    key.equalsIgnoreCase("pwdLastSuccess") ||
                                    key.equalsIgnoreCase("pwdReset"))
                                continue;

                            // Special handling of 'entitledCapabilites' requires since they need to be DNs
                            if (key.equalsIgnoreCase(Identity.ATTR_CAPABILITIES))
                            {
                                Set<String> dnList = new HashSet<>();
                                for (String capabilityName : attributes.get(key))
                                {
                                    // Must convert the capability name to corresponding DN
                                    for (String capKey : capabilityCache.keySet())
                                    {
                                        if (capabilityCache.get(capKey).equalsIgnoreCase(capabilityName))
                                            dnList.add(capKey);
                                    }
                                }

                                // Add the list of DN's for the capabilities
                                entry.add(key, dnList.toArray(new String[dnList.size()]));
                            }
                            else
                            {
                                Set<String> strings = attributes.get(key);
                                entry.add(key, strings.toArray(new String[strings.size()]));
                            }
                        }
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }


        // Retrieve the DN of the domain-specific Password Policy, if there is one
        String passwordPolicyDn;
        try
        {
            passwordPolicyDn = ldapConnectionTemplate.lookup(
                    ldapConnectionTemplate.newDn("ads-pwdId=" + identity.getDomain() + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    new String[]{"ads-pwdid"},        //attribute list
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.getDn().toString();
                        }
                    }
            );
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }

        // Apply the domain-specific Password Policy if one was found else
        // the account will be governed by the global Password Policy
        if (passwordPolicyDn != null)
        {
            final String policyDn = passwordPolicyDn;
            ModifyResponse modResponse = ldapConnectionTemplate.modify(
                    ldapConnectionTemplate.newDn("uid=" + identity.getUsername() + ",ou=users,o=" + identity.getDomain() + "," + baseDN),
                    new RequestBuilder<ModifyRequest>()
                    {
                        @Override
                        public void buildRequest(ModifyRequest request) throws LdapException
                        {
                            request.add("pwdPolicySubentry", policyDn);
                        }
                    }
            );

            if (modResponse.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
            {
                String msg;
                if ((msg = modResponse.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(modResponse.getLdapResult().getResultCode(), msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }

        // return the newly created identity
        return getIdentity(identity.getUsername(), identity.getDomain());
    }


    /**
     * Deletes the related LDAP entity for the specified identity
     *
     * @param username
     * @param domain
     * @throws LdapIdentityBackendException
     */
    public void deleteIdentity(String username, String domain) throws LdapIdentityBackendException
    {
        // Delete any nested elements that remain before deleting the identity itself
        deleteChildren("uid=" + username + ",ou=users,o=" + domain + "," + baseDN);


        // Delete the identity itself
        DeleteResponse response = ldapConnectionTemplate.delete(
                ldapConnectionTemplate.newDn("uid=" + username + ",ou=users,o=" + domain + "," + baseDN));
        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Updates an existing LDAP entity for the specified identity
     *
     * @param identity
     * @return Identity
     * @throws LdapIdentityBackendException
     */
    public Identity updateIdentity(final Identity identity) throws LdapIdentityBackendException
    {
        // retrieve the current details about the capability
        final Identity currIdentity = getIdentity(identity.getUsername(), identity.getDomain());
        if (currIdentity == null)
        {
            String msg = "NO_SUCH_OBJECT: failed for MessageType : MOD_REQUEST\nMessage ID : 6\n    Mod request\n        Entry : 'uid=" +
                    identity.getUsername() + ",ou=users,o=" + identity.getDomain() + "," + baseDN +
                    "'\norg.apache.directory.api.ldap.model.message.DeleteRequestImpl@23205551: Attempt to lookup non-existant entry: uid=" +
                    identity.getUsername() + ",ou=users,o=" + identity.getDomain() + "," + baseDN;
            LdapOperationException ldapExcept = new LdapOperationException(ResultCodeEnum.NO_SUCH_OBJECT, msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }


        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("uid=" + identity.getUsername() + ",ou=users,o=" + identity.getDomain() + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        Map<String, Set<String>> currAttributes = currIdentity.getAttributes();
                        Map<String, Set<String>> newAttributes = identity.getAttributes();

                        for (String key : newAttributes.keySet())
                        {
                            // Skip any special read-only attributes
                            if (key.equalsIgnoreCase("createTimestamp") ||
                                    key.equalsIgnoreCase("pwdChangedTime") ||
                                    key.equalsIgnoreCase("pwdAccountLockedTime") ||
                                    key.equalsIgnoreCase("pwdFailureTime") ||
                                    key.equalsIgnoreCase("pwdStartTime") ||
                                    key.equalsIgnoreCase("pwdEndTime") ||
                                    key.equalsIgnoreCase("pwdLastSuccess") ||
                                    key.equalsIgnoreCase("pwdReset"))
                                continue;

                            // Special handling of 'entitledCapabilites' requires since they need to be DNs
                            if (key.equalsIgnoreCase(Identity.ATTR_CAPABILITIES))
                            {
                                Set<String> dnList = new HashSet<>();
                                for (String capabilityName : newAttributes.get(key))
                                {
                                    // Must convert the capability name to corresponding DN
                                    for (String capKey : capabilityCache.keySet())
                                    {
                                        if (capabilityCache.get(capKey).equalsIgnoreCase(capabilityName))
                                            dnList.add(capKey);
                                    }
                                }

                                // Add the list of DN's for the capabilities, else replace them
                                request.replace(key, dnList.toArray(new String[dnList.size()]));
                            }
                            else
                            {
                                // Add a missing attribute
                                request.replace(key, newAttributes.get(key).toArray(new String[0]));
                            }
                        }

                        // Handle any removals
                        for (String key : currAttributes.keySet())
                        {
                            // Can't remove mandatory attributes
                            if (key.equalsIgnoreCase(Identity.ATTR_FULLNAME) ||
                                    key.equalsIgnoreCase(Identity.ATTR_FIRSTNAME) ||
                                    key.equalsIgnoreCase(Identity.ATTR_LASTNAME) ||
                                    key.equalsIgnoreCase(Identity.ATTR_CAPABILITIES))
                                continue;

                            // Skip any special read-only attributes
                            if (key.equalsIgnoreCase("createTimestamp") ||
                                    key.equalsIgnoreCase("pwdChangedTime") ||
                                    key.equalsIgnoreCase("pwdAccountLockedTime") ||
                                    key.equalsIgnoreCase("pwdFailureTime") ||
                                    key.equalsIgnoreCase("pwdStartTime") ||
                                    key.equalsIgnoreCase("pwdEndTime") ||
                                    key.equalsIgnoreCase("pwdLastSuccess") ||
                                    key.equalsIgnoreCase("pwdReset"))
                                continue;

                            if (newAttributes.get(key) == null)
                                request.replace(key);
                        }
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // return the newly updated identity
        return getIdentity(identity.getUsername(), identity.getDomain());
    }


    /**
     * Retrieves a list of names for all domains defined
     *
     * @return List<String>
     * @throws LdapIdentityBackendException
     */
    public List<String> listAllDomains() throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search(baseDN,
                    "(objectClass=organization)", SearchScope.ONELEVEL,
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.get("o").getString();
                        }
                    });
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }


    /**
     * Retrieves a list of Domain objects for all domains
     *
     * @return
     * @throws LdapIdentityBackendException
     */
    public List<Domain> getAllDomains() throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search(baseDN,
                    "(objectclass=organization)",
                    SearchScope.SUBTREE,
                    domainEntryMapper);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }

    /**
     * Retrieves details about the specified domain
     *
     * @param domainName
     * @return Domain
     * @throws LdapIdentityBackendException
     */
    public Domain getDomain(String domainName) throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.lookup(
                    ldapConnectionTemplate.newDn("o=" + domainName + "," + baseDN),
                    domainEntryMapper);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }


    /**
     * Creates an LDAP entity to represent the specified Domain and a
     * corresponding identity for domain-level administration
     *
     * @param domain
     * @return Domain
     * @throws LdapIdentityBackendException
     */
    public Domain createDomain(final Domain domain) throws LdapIdentityBackendException
    {
        AddResponse response = ldapConnectionTemplate.add(
                ldapConnectionTemplate.newDn("o=" + domain.getDomainName() + "," + baseDN),
                new RequestBuilder<AddRequest>()
                {
                    @Override
                    public void buildRequest(AddRequest request) throws LdapException
                    {
                        Entry entry = request.getEntry();
                        entry.add("objectClass", "top", "organization", "argosAuthPolicy");
                        entry.add("o", domain.getDomainName());
                        entry.add(Domain.ATTR_DESCRIPTION, domain.getDescription());

                        Map<String, Set<String>> attributes = domain.getAttributes();
                        for (Map.Entry<String, Set<String>> e : attributes.entrySet())
                        {
                            Set<String> value = e.getValue();
                            entry.add(e.getKey(), value.toArray(new String[value.size()]));
                        }
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // Create the organizational unit which will host the users for the domain
        AddResponse ouResponse = ldapConnectionTemplate.add(
                ldapConnectionTemplate.newDn("ou=users,o=" + domain.getDomainName() + "," + baseDN),
                new RequestBuilder<AddRequest>()
                {
                    @Override
                    public void buildRequest(AddRequest request) throws LdapException
                    {
                        Entry entry = request.getEntry();
                        entry.add("objectClass", "top", "organizationalUnit");
                        entry.add("ou", "users");
                    }
                }
        );

        if (ouResponse.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = ouResponse.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(ouResponse.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // Check whether to automatically create the domain administrators account
        boolean autoCreateAdmin = Boolean.valueOf(
                Configuration.getInstance().getString("ldapAutoCreateAdmin", "" + false));
        if (autoCreateAdmin)
        {
            // Build the identity for the administrator of the domain
            Identity adminIdentity = new Identity();
            Map<String, Set<String>> attributes = new HashMap<>();

            attributes.put(Identity.ATTR_FULLNAME, Collections.singleton(domain.getDomainName() + " Domain Administrator"));
            attributes.put(Identity.ATTR_FIRSTNAME, Collections.singleton(domain.getDomainName()));
            attributes.put(Identity.ATTR_LASTNAME, Collections.singleton("Domain Administrator"));
            attributes.put(Identity.ATTR_DESCRIPTION, Collections.singleton("Administrative account for " + domain.getDomainName()));
            attributes.put(Identity.ATTR_CAPABILITIES, Collections.singleton("domainAdmin"));

            adminIdentity.setDomain(domain.getDomainName());
            adminIdentity.setUsername("admin");
            adminIdentity.setAttributes(attributes);

            // Add the administrative account
            createIdentity(adminIdentity);
        }

        // return the newly created domain
        return getDomain(domain.getDomainName());
    }


    /**
     * Deletes the LDAP entity that represents the specified domain
     *
     * @param domain
     * @throws LdapIdentityBackendException
     */
    public void deleteDomain(String domain) throws LdapIdentityBackendException
    {
        // Delete any nested elements that remain
        try
        {
            deleteChildren("o=" + domain + "," + baseDN);
        }
        catch (LdapIdentityBackendException e)
        {
            throw e;
        }

        // Delete the domain itself
        DeleteResponse response = ldapConnectionTemplate.delete(
                ldapConnectionTemplate.newDn("o=" + domain + "," + baseDN));
        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Updates the existing LDAP entity that represents the domain with new attributes
     *
     * @param domain
     * @return Domain
     * @throws LdapIdentityBackendException
     */
    public Domain updateDomain(final Domain domain) throws LdapIdentityBackendException
    {
        // retrieve the current details about the capability
        final Domain currDomain = getDomain(domain.getDomainName());
        if (currDomain == null)
        {
            String msg = "NO_SUCH_OBJECT: failed for MessageType : MOD_REQUEST\nMessage ID : 6\n    Mod request\n        Entry : 'o=" +
                    domain.getDomainName() + "," + baseDN +
                    "'\norg.apache.directory.api.ldap.model.message.DeleteRequestImpl@23205551: Attempt to lookup non-existant entry: o=" +
                    domain.getDomainName() + "," + baseDN;
            LdapOperationException ldapExcept = new LdapOperationException(ResultCodeEnum.NO_SUCH_OBJECT, msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("o=" + domain.getDomainName() + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        // build up the list of attributes that must be updated
                        if (!currDomain.getDescription().equalsIgnoreCase(domain.getDescription()))
                            request.replace(Domain.ATTR_DESCRIPTION, domain.getDescription());

                        Map<String, Set<String>> currAttributes = currDomain.getAttributes();
                        Map<String, Set<String>> newAttributes = domain.getAttributes();

                        for (Map.Entry<String, Set<String>> e : newAttributes.entrySet())
                        {
                            Set<String> value = e.getValue();
                            request.replace(e.getKey(), value.toArray(new String[value.size()]));
                        }

                        // Handle any removals
                        for (String key : currAttributes.keySet())
                        {
                            // Can't remove mandatory attributes
                            if (key.equalsIgnoreCase(Domain.ATTR_NAME) ||
                                    key.equalsIgnoreCase("twoFactorAuth"))
                                continue;

                            if (newAttributes.get(key) == null)
                                request.replace(key);
                        }
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // return the newly modified domain
        return getDomain(domain.getDomainName());
    }


    /**
     * Returns a list of Capability objects
     *
     * @return List<Capability>
     * @throws LdapIdentityBackendException
     */
    public List<Capability> getCapabilities() throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search("ou=capabilities," + baseDN,
                    "(objectclass=argosCapability)",
                    SearchScope.SUBTREE,
                    capabilityEntryMapper);
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }
    }


    /**
     * Returns a list of names of Capabilities that have been defined
     *
     * @return List<String>
     * @throws LdapIdentityBackendException
     */
    public List<String> listCapabilities() throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.search("ou=capabilities," + baseDN, "(objectClass=argosCapability)", SearchScope.ONELEVEL,
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.get("cn").getString();
                        }
                    }
            );
        }
        catch (Exception e)
        {
            log.error("Get Capabilities", e);
            throw new LdapIdentityBackendException("", e);
        }
    }


    /**
     * Returns a Capability object containing details about the specified capability
     *
     * @param capabilityName
     * @return Capability
     * @throws LdapIdentityBackendException
     */
    public Capability getCapability(String capabilityName) throws LdapIdentityBackendException
    {
        try
        {
            return ldapConnectionTemplate.lookup(
                    ldapConnectionTemplate.newDn("cn=" + capabilityName + ",ou=capabilities," + baseDN),
                    capabilityEntryMapper);
        }
        catch (Exception e)
        {
            log.error("Get Capability", e);
            throw new LdapIdentityBackendException("Get Capability", e);
        }
    }


    /**
     * Creates an LDAP entity that represents the corresponding Capability
     *
     * @param capability
     * @throws LdapIdentityBackendException
     */
    public void createCapability(final Capability capability) throws LdapIdentityBackendException
    {
        AddResponse response = ldapConnectionTemplate.add(
                ldapConnectionTemplate.newDn("cn=" + capability.getCapabilityName() + ",ou=capabilities," + baseDN),
                new RequestBuilder<AddRequest>()
                {
                    @Override
                    public void buildRequest(AddRequest request) throws LdapException
                    {
                        Entry entry = request.getEntry();
                        entry.add("objectClass", "top", "argosCapability");
                        entry.add("cn", capability.getCapabilityName());
                        entry.add(Capability.ATTR_DESCRIPTION, capability.getDescription());

                        Map<String, Set<String>> attributes = capability.getAttributes();
                        for (Map.Entry<String, Set<String>> e : attributes.entrySet())
                        {
                            Set<String> var = e.getValue();
                            entry.add(e.getKey(), var.toArray(new String[var.size()]));
                        }
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // Add the entry for this capability to the cache of capabilities
        if (capabilityCache.get("cn=" + capability.getCapabilityName() + ",ou=capabilities," + baseDN) == null)
            capabilityCache.put("cn=" + capability.getCapabilityName() + ",ou=capabilities," + baseDN, capability.getCapabilityName());

    }


    /**
     * Deletes an existing LDAP entity that corresponds to the specified capability
     *
     * @param capabilityName
     * @throws LdapIdentityBackendException
     */
    public void deleteCapability(String capabilityName) throws LdapIdentityBackendException
    {
        // Delete any nested elements that remain
        deleteChildren("cn=" + capabilityName + ",ou=capabilities," + baseDN);

        // Delete the Capability itself
        DeleteResponse response = ldapConnectionTemplate.delete(
                ldapConnectionTemplate.newDn("cn=" + capabilityName + ",ou=capabilities," + baseDN));

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // Remove the entry for this capability from the cache of capabilities
        if (capabilityCache.get("cn=" + capabilityName + ",ou=capabilities," + baseDN) != null)
            capabilityCache.remove("cn=" + capabilityName + ",ou=capabilities," + baseDN);
    }


    /**
     * Updates an existing LDAP entity for the specified Capability
     *
     * @param capability
     * @throws LdapIdentityBackendException
     */
    public void updateCapability(final Capability capability) throws LdapIdentityBackendException
    {
        // retrieve the current details about the capability
        final Capability currCapability = getCapability(capability.getCapabilityName());
        if (currCapability == null)
        {
            String msg = "NO_SUCH_OBJECT: failed for MessageType : MOD_REQUEST\nMessage ID : 6\n    Mod request\n        Entry : 'cn=" +
                    capability.getCapabilityName() + "," + baseDN +
                    "'\norg.apache.directory.api.ldap.model.message.DeleteRequestImpl@23205551: Attempt to lookup non-existant entry: cn=" +
                    capability.getCapabilityName() + "," + baseDN;
            LdapOperationException ldapExcept = new LdapOperationException(ResultCodeEnum.NO_SUCH_OBJECT, msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        ModifyResponse response = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("cn=" + capability.getCapabilityName() + ",ou=capabilities," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        // build up the list of attributes that must be updated
                        if (!currCapability.getDescription().equalsIgnoreCase(capability.getDescription()))
                            request.replace(Capability.ATTR_DESCRIPTION, capability.getDescription());

                        Map<String, Set<String>> currAttributes = currCapability.getAttributes();
                        Map<String, Set<String>> newAttributes = capability.getAttributes();

                        // Add a missing attribute
                        for (Map.Entry<String, Set<String>> e : newAttributes.entrySet())
                        {
                            Set<String> value = e.getValue();
                            request.replace(e.getKey(), value.toArray(new String[value.size()]));
                        }

                        // Handle any removals
                        for (String key : currAttributes.keySet())
                        {
                            // Can't remove mandatory attributes
                            if (key.equalsIgnoreCase("cn") || key.equalsIgnoreCase(Capability.ATTR_DESCRIPTION))
                                continue;

                            if (newAttributes.get(key) == null)
                                request.replace(key);
                        }
                    }
                }
        );

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Lookup zero or more LDAP entities representing an Identity based on the parameters
     *
     * @param parameters
     * @return List<Identity>
     * @throws LdapIdentityBackendException
     */
    public List<Identity> search(Map<String, String> parameters) throws LdapIdentityBackendException
    {
        return null;
    }

    /**
     * Returns the Password Policy for the specified name or globally
     *
     * @param policyName Name of the Password Policy to retrieve
     *                   or null to retrieve the global Password Policy
     * @return PasswordPolicy object
     */
    public PasswordPolicy getPasswordPolicy(String policyName) throws LdapIdentityBackendException
    {
        PasswordPolicy policy;
        try
        {
            if (policyName == null)
            {
                policy = ldapConnectionTemplate.lookup(
                        ldapConnectionTemplate.newDn("ads-pwdId=default,ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                        passwordPolicyEntryMapper);
            }
            else
            {
                policy = ldapConnectionTemplate.lookup(
                        ldapConnectionTemplate.newDn("ads-pwdId=" + policyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                        passwordPolicyEntryMapper);
            }

            // Check the Aniketos extensions to the password policy for 2-factor authentication
            if (policy != null && policyName != null)
            {
                // Check the domain to see if has the 2-factor password policy set
                Domain domain = getDomain(policyName);
                if (domain != null)
                {
                    if (domain.getAttributes().get("twofactorauth") != null)
                    {
                        String[] twoFactorAuth = domain.getAttributes().get("twofactorauth").toArray(new String[0]);
                        if (twoFactorAuth != null && twoFactorAuth.length > 0)
                        {
                            if (Integer.valueOf(twoFactorAuth[0]) == 0)
                                policy.setTwoFactorAuthn(TOTP.DISABLED);
                            if (Integer.valueOf(twoFactorAuth[0]) == 1)
                                policy.setTwoFactorAuthn(TOTP.ENABLED);
                            if (Integer.valueOf(twoFactorAuth[0]) == 2)
                                policy.setTwoFactorAuthn(TOTP.REQUIRED);
                        }
                    }
                }
            }

            return policy;
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("Get Password Policy", e);
        }
    }

    /**
     * Returns the Lockout Policy for the specified policy or global
     *
     * @param policyName Name of the policy for which to receive the
     *                   associated Lockout Policy or null to retrieve
     *                   the global Lockout Policy
     * @return
     */
    public LockoutPolicy getLockoutPolicy(String policyName) throws LdapIdentityBackendException
    {
        LockoutPolicy policy;
        try
        {
            if (policyName == null)
            {
                policy = ldapConnectionTemplate.lookup(
                        ldapConnectionTemplate.newDn("ads-pwdId=default,ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                        lockoutPolicyEntryMapper);
            }
            else
            {
                policy = ldapConnectionTemplate.lookup(
                        ldapConnectionTemplate.newDn("ads-pwdId=" + policyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                        lockoutPolicyEntryMapper);
            }

            return policy;
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("Get Lockout Policy", e);
        }
    }

    /**
     * Updates the named or global Password Policy.
     * <p/>
     * A Password Policy with that name will be created if one doesn't exist
     *
     * @param policy
     * @param policyName
     */
    public void setPasswordPolicy(final String policyName, final PasswordPolicy policy) throws LdapIdentityBackendException
    {
        // Check to see if the domain exists before allowing a domain Password Policy to be set
        if (policyName != null)
        {
            String domainDn = ldapConnectionTemplate.lookup(
                    ldapConnectionTemplate.newDn("o=" + policyName + "," + baseDN),
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.getDn().toString();
                        }
                    }
            );

            // Throw an exception if the domain doesn't exist
            if (domainDn == null)
            {
                String msg = "NO_SUCH_OBJECT: failed for MessageType : LOOKUP_REQUEST\nMessage ID : 6\n    Lookup request\n        Entry : 'o=" +
                        policyName + "," + baseDN +
                        "'\norg.apache.directory.api.ldap.model.message.DeleteRequestImpl@23205551: Attempt to lookup non-existant entry: o=" +
                        policyName + "," + baseDN;
                LdapOperationException ldapExcept = new LdapOperationException(ResultCodeEnum.NO_SUCH_OBJECT, msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }

        // get the current version of the Password Policy for the target
        final PasswordPolicy currPolicy = getPasswordPolicy(policyName);

        // If there is currently no Password Policy with that name, then we're adding one
        if (currPolicy == null && policyName != null)
        {
            AddResponse response = ldapConnectionTemplate.add(
                    ldapConnectionTemplate.newDn("ads-pwdId=" + policyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    new RequestBuilder<AddRequest>()
                    {
                        @Override
                        public void buildRequest(AddRequest request) throws LdapException
                        {
                            Entry entry = request.getEntry();
                            entry.add("objectClass", "top", "ads-base", "ads-passwordPolicy");
                            entry.add("ads-pwdId", policyName);
                            entry.add("ads-pwdAttribute", "userPassword");
                            entry.add("ads-pwdValidator", "org.apache.directory.server.core.api.authn.ppolicy.DefaultPasswordValidator");

                            if (policy.getPolicyEnabled())
                                entry.add("ads-enabled", "TRUE");
                            else
                                entry.add("ads-enabled", "FALSE");

                            if (policy.getMinAge() > 0)
                                entry.add("ads-pwdMinAge", policy.getMinAge().toString());
                            if (policy.getMaxAge() > 0)
                                entry.add("ads-pwdMaxAge", policy.getMaxAge().toString());
                            if (policy.getQualityCheckLevel() == PasswordQualityCheck.RELAXED)
                                entry.add("ads-pwdCheckQuality", "1");
                            if (policy.getQualityCheckLevel() == PasswordQualityCheck.STRICT)
                                entry.add("ads-pwdCheckQuality", "2");
                            if (policy.getMinLength() > 0)
                                entry.add("ads-pwdMinLength", policy.getMinLength().toString());
                            if (policy.getMaxLength() > 0)
                                entry.add("ads-pwdMaxLength", policy.getMaxLength().toString());
                            if (policy.getExpireWarning() > 0)
                                entry.add("ads-pwdExpireWarning", policy.getExpireWarning().toString());
                            if (policy.getGraceAuthnLimit() > 0)
                                entry.add("ads-pwdGraceAuthnLimit", policy.getGraceAuthnLimit().toString());
                            if (policy.getGraceExpiry() > 0)
                                entry.add("ads-pwdGraceExpiry", policy.getGraceExpiry().toString());
                            if (policy.getMustChange())
                                entry.add("ads-pwdMustChange", "TRUE");
                            if (!policy.getAllowUserChange())
                                entry.add("ads-pwdAllowUserChange", "FALSE");
                            if (policy.getSafeModify())
                                entry.add("ads-pwdSafeModify", "TRUE");
                        }
                    }
            );

            if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
            {
                String msg;
                if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }
        else
        {
            String tmpPolicyName;
            if (policyName == null)
                tmpPolicyName = "default";
            else
                tmpPolicyName = policyName;

            ModifyResponse response = ldapConnectionTemplate.modify(
                    ldapConnectionTemplate.newDn("ads-pwdId=" + tmpPolicyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    new RequestBuilder<ModifyRequest>()
                    {
                        @Override
                        public void buildRequest(ModifyRequest request) throws LdapException
                        {
                            if (!policy.getPolicyEnabled().equals(currPolicy.getPolicyEnabled()))
                                request.replace("ads-enabled", policy.getPolicyEnabled() ? "TRUE" : "FALSE");

                            if (!policy.getMinAge().equals(currPolicy.getMinAge()))
                                request.replace("ads-pwdMinAge", policy.getMinAge().toString());

                            if (!policy.getMaxAge().equals(currPolicy.getMaxAge()))
                                request.replace("ads-pwdMaxAge", policy.getMaxAge().toString());

                            if (policy.getQualityCheckLevel() != currPolicy.getQualityCheckLevel())
                            {
                                if (policy.getQualityCheckLevel() == PasswordQualityCheck.DISABLED)
                                    request.replace("ads-pwdCheckQuality", "0");
                                if (policy.getQualityCheckLevel() == PasswordQualityCheck.RELAXED)
                                    request.replace("ads-pwdCheckQuality", "1");
                                if (policy.getQualityCheckLevel() == PasswordQualityCheck.STRICT)
                                    request.replace("ads-pwdCheckQuality", "2");
                            }

                            if (!policy.getMinLength().equals(currPolicy.getMinLength()))
                                request.replace("ads-pwdMinLength", policy.getMinLength().toString());

                            if (!policy.getMaxLength().equals(currPolicy.getMaxLength()))
                                request.replace("ads-pwdMaxLength", policy.getMaxLength().toString());

                            if (!policy.getExpireWarning().equals(currPolicy.getExpireWarning()))
                                request.replace("ads-pwdExpireWarning", policy.getExpireWarning().toString());

                            if (!policy.getGraceAuthnLimit().equals(currPolicy.getGraceAuthnLimit()))
                                request.replace("ads-pwdGraceAuthNLimit", policy.getGraceAuthnLimit().toString());

                            if (!policy.getGraceExpiry().equals(currPolicy.getGraceExpiry()))
                                request.replace("ads-pwdGraceExpiry", policy.getGraceExpiry().toString());

                            if (!policy.getMustChange().equals(currPolicy.getMustChange()))
                                request.replace("ads-pwdMustChange", policy.getMustChange() ? "TRUE" : "FALSE");

                            if (!policy.getAllowUserChange().equals(currPolicy.getAllowUserChange()))
                                request.replace("ads-pwdAllowUserChange", policy.getAllowUserChange() ? "TRUE" : "FALSE");

                            if (!policy.getSafeModify().equals(currPolicy.getSafeModify()))
                                request.replace("ads-pwdSafeModify", policy.getSafeModify() ? "TRUE" : "FALSE");
                        }
                    }
            );

            if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
            {
                String msg;
                if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }

        if (policyName != null)
        {
            // Check if the Aniketos extensions to Password Policy needs to be updated
            ModifyResponse response = ldapConnectionTemplate.modify(
                    ldapConnectionTemplate.newDn("o=" + policyName + "," + baseDN),
                    new RequestBuilder<ModifyRequest>()
                    {
                        @Override
                        public void buildRequest(ModifyRequest request) throws LdapException
                        {
                            if (policy.getTwoFactorAuthn() == TOTP.DISABLED)
                                request.replace("twoFactorAuth", "0");
                            if (policy.getTwoFactorAuthn() == TOTP.ENABLED)
                                request.replace("twoFactorAuth", "1");
                            if (policy.getTwoFactorAuthn() == TOTP.REQUIRED)
                                request.replace("twoFactorAuth", "2");
                        }
                    }
            );

            if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS &&
                    response.getLdapResult().getResultCode() != ResultCodeEnum.NO_SUCH_OBJECT)
            {
                String msg;
                if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
                log.error(msg + ": " + policyName, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }
    }

    /**
     * Updates the named or global Lockout Policy.
     * <p/>
     * A Lockout Policy with that name will be created if one doesn't exist
     *
     * @param policy
     * @param policyName
     */
    public void setLockoutPolicy(final String policyName, final LockoutPolicy policy) throws LdapIdentityBackendException
    {
        // Check to see if the domain exists before allowing a domain Lockout Policy to be set
        if (policyName != null)
        {
            String domainDn = ldapConnectionTemplate.lookup(
                    ldapConnectionTemplate.newDn("o=" + policyName + "," + baseDN),
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.getDn().toString();
                        }
                    }
            );

            // Throw an exception if the domain doesn't exist
            if (domainDn == null)
            {
                String msg = "NO_SUCH_OBJECT: failed for MessageType : MOD_REQUEST\nMessage ID : 6\n    Mod request\n        Entry : 'o=" +
                        policyName + "," + baseDN +
                        "'\norg.apache.directory.api.ldap.model.message.DeleteRequestImpl@23205551: Attempt to lookup non-existant entry: o=" +
                        policyName + "," + baseDN;
                LdapOperationException ldapExcept = new LdapOperationException(ResultCodeEnum.NO_SUCH_OBJECT, msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }

        // get the current version of the Lockout Policy for the target
        final LockoutPolicy currPolicy = getLockoutPolicy(policyName);

        // If there is currently no Policy Policy with that name, then we're adding one
        if (currPolicy == null && policyName != null)
        {
            AddResponse response = ldapConnectionTemplate.add(
                    ldapConnectionTemplate.newDn("ads-pwdId=" + policyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    new RequestBuilder<AddRequest>()
                    {
                        @Override
                        public void buildRequest(AddRequest request) throws LdapException
                        {
                            Entry entry = request.getEntry();
                            entry.add("objectClass", "top", "ads-base", "ads-passwordPolicy");
                            entry.add("ads-pwdId", policyName);
                            entry.add("ads-pwdAttribute", "userPassword");
                            entry.add("ads-pwdValidator", "org.apache.directory.server.core.api.authn.ppolicy.DefaultPasswordValidator");

                            if (policy.getPolicyEnabled())
                            {
                                entry.add("ads-enabled", "TRUE");
                                entry.add("ads-pwdLockout", policy.getPolicyEnabled() ? "TRUE" : "FALSE");
                            }

                            if (policy.getPasswordsInHistory() > 0)
                                entry.add("ads-pwdInHistory", policy.getPasswordsInHistory().toString());
                            if (policy.getLockoutDuration() > 0)
                                entry.add("ads-pwdLockoutDuration", policy.getLockoutDuration().toString());
                            if (policy.getMaxAttempts() > 0)
                                entry.add("ads-pwdMaxFailure", policy.getLockoutDuration().toString());
                            if (policy.getFailureCountInterval() > 0)
                                entry.add("ads-pwdFailureCountInterval", policy.getFailureCountInterval().toString());
                            if (policy.getMinDelay() > 0 && policy.getMaxDelay() > 0)
                            {
                                if (policy.getMinDelay() > 0)
                                    entry.add("ads-pwdMinDelay", policy.getMinDelay().toString());
                                if (policy.getMaxDelay() > 0)
                                    entry.add("ads-pwdMaxDelay", policy.getMaxDelay().toString());
                            }
                            if (policy.getMaxIdle() > 0)
                                entry.add("ads-pwdMaxIdle", policy.getMaxIdle().toString());
                        }
                    }
            );

            if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
            {
                String msg;
                if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }
        else
        {
            String tmpPolicyName;
            if (policyName == null)
                tmpPolicyName = "default";
            else
                tmpPolicyName = policyName;


            ModifyResponse response = ldapConnectionTemplate.modify(
                    ldapConnectionTemplate.newDn("ads-pwdId=" + tmpPolicyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    new RequestBuilder<ModifyRequest>()
                    {
                        @Override
                        public void buildRequest(ModifyRequest request) throws LdapException
                        {
                            if (!policy.getPolicyEnabled().equals(currPolicy.getPolicyEnabled()))
                                request.replace("ads-pwdLockout", policy.getPolicyEnabled() ? "TRUE" : "FALSE");

                            if (!policy.getPasswordsInHistory().equals(currPolicy.getPasswordsInHistory()))
                                request.replace("ads-pwdInHistory", policy.getPasswordsInHistory().toString());

                            if (!policy.getLockoutDuration().equals(currPolicy.getLockoutDuration()))
                                request.replace("ads-pwdLockoutDuration", policy.getLockoutDuration().toString());

                            if (!policy.getMaxAttempts().equals(currPolicy.getMaxAttempts()))
                                request.replace("ads-pwdMaxFailure", policy.getMaxAttempts().toString());

                            if (!policy.getFailureCountInterval().equals(currPolicy.getFailureCountInterval()))
                                request.replace("ads-pwdFailureCountInterval", policy.getFailureCountInterval().toString());

                            if (!policy.getMinDelay().equals(currPolicy.getMinDelay()))
                                request.replace("ads-pwdMinDelay", policy.getMinDelay().toString());

                            if (policy.getMinDelay() > 0 && policy.getMaxDelay() > 0)
                            {
                                if (!policy.getMinDelay().equals(currPolicy.getMinDelay()))
                                    request.replace("ads-pwdMinDelay", policy.getMinDelay().toString());
                                if (!policy.getMaxDelay().equals(currPolicy.getMaxDelay()))
                                    request.replace("ads-pwdMaxDelay", policy.getMaxDelay().toString());
                            }

                            if (!policy.getMaxIdle().equals(currPolicy.getMaxIdle()))
                                request.replace("ads-pwdMaxIdle", policy.getMaxIdle().toString());
                        }
                    }
            );

            if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
            {
                String msg;
                if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }
    }


    /**
     * Deletes a named Password Policy and its corresponding Lockout Policy
     *
     * @param policyName
     * @throws LdapIdentityBackendException
     */
    public void deletePasswordPolicy(String policyName) throws LdapIdentityBackendException
    {
        // Delete any nested elements that remain
        deleteChildren("ads-pwdId=" + policyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config");

        // Delete the Password Policy itself
        DeleteResponse response = ldapConnectionTemplate.delete(
                ldapConnectionTemplate.newDn("ads-pwdId=" + policyName + ",ou=passwordPolicies,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"));

        if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }

        // Remove the Aniketos extensions to Password Policy
        ModifyResponse modResponse = ldapConnectionTemplate.modify(
                ldapConnectionTemplate.newDn("o=" + policyName + "," + baseDN),
                new RequestBuilder<ModifyRequest>()
                {
                    @Override
                    public void buildRequest(ModifyRequest request) throws LdapException
                    {
                        request.replace("twoFactorAuth");
                    }
                }
        );

        if (modResponse.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
        {
            String msg;
            if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                msg = "";

            LdapOperationException ldapExcept = new LdapOperationException(modResponse.getLdapResult().getResultCode(), msg);
            log.error(msg, ldapExcept);
            throw new LdapIdentityBackendException(msg, ldapExcept);
        }
    }


    /**
     * Recursive depth walk to delete children nodes before deleting its parent
     *
     * @param parentDn
     */
    private void deleteChildren(String parentDn) throws LdapIdentityBackendException
    {
        List<String> dnList;
        try
        {
            dnList = ldapConnectionTemplate.search(parentDn,
                    "(objectClass=*)", SearchScope.ONELEVEL,
                    new EntryMapper<String>()
                    {
                        @Override
                        public String map(Entry entry) throws LdapException
                        {
                            return entry.getDn().toString();
                        }
                    });
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new LdapIdentityBackendException("", e);
        }

        for (String dn : dnList)
        {
            deleteChildren(dn);
            log.info("deleting node" + dn);
            DeleteResponse response = ldapConnectionTemplate.delete(
                    ldapConnectionTemplate.newDn(dn));
            if (response.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS)
            {
                String msg;
                if ((msg = response.getLdapResult().getDiagnosticMessage()) == null)
                    msg = "";

                LdapOperationException ldapExcept = new LdapOperationException(response.getLdapResult().getResultCode(), msg);
                log.error(msg, ldapExcept);
                throw new LdapIdentityBackendException(msg, ldapExcept);
            }
        }


    }
}
