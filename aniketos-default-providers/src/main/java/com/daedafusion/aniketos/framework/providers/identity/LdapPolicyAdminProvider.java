package com.daedafusion.aniketos.framework.providers.identity;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.admin.providers.PolicyAdminProvider;
import com.daedafusion.security.common.LockoutPolicy;
import com.daedafusion.security.common.PasswordPolicy;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/29/14.
 */
public class LdapPolicyAdminProvider extends AbstractProvider implements PolicyAdminProvider
{
    private static final Logger log = Logger.getLogger(LdapPolicyAdminProvider.class);

    // Get an instance to the Ldap backend singleton
    LdapIdentityBackend ldapBackEnd = LdapIdentityBackend.getInstance();

    @Override
    public LockoutPolicy getLockoutPolicy( String domainName )
    {
    	try {
    		return ldapBackEnd.getLockoutPolicy( domainName );
    	}
    	catch ( LdapIdentityBackendException e ){
    		log.error( e );
    		return null;
    	}
    }

    @Override
    public void setLockoutPolicy(String domainName, LockoutPolicy policy)
    {
    	try {
    		ldapBackEnd.setLockoutPolicy( domainName, policy);
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    	}

    }

    @Override
    public PasswordPolicy getPasswordPolicy( String domainName )
    {
    	try {
    		return ldapBackEnd.getPasswordPolicy( domainName );
    	}
    	catch ( LdapIdentityBackendException e ) {
    		log.error( e );
    		return null;
    	}
    }

    @Override
    public void setPasswordPolicy(String domainName, PasswordPolicy policy)
    {
    	try {
    		ldapBackEnd.setPasswordPolicy( domainName, policy );
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    	}
    }
}
