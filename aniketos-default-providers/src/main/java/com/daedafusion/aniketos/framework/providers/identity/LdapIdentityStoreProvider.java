package com.daedafusion.aniketos.framework.providers.identity;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.identity.providers.IdentityStoreProvider;
import org.apache.log4j.Logger;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class LdapIdentityStoreProvider extends AbstractProvider implements IdentityStoreProvider
{
    private static final Logger log = Logger.getLogger(LdapIdentityStoreProvider.class);

    // Get an instance to the Ldap backend singleton
    LdapIdentityBackend ldapBackEnd = LdapIdentityBackend.getInstance();

    @Override
    public Identity getIdentity(Subject subject, String userName, String domainName)
    {
    	try {
    		return ldapBackEnd.getIdentity( userName, domainName );
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    		return null;
    	}
    }

    @Override
    public List<Identity> getIdentitiesForDomain(Subject subject, String domain)
    {
        throw new NotImplementedException();
    }

    @Override
    public void setPassword(Subject subject, String userName, String domainName, String password)
    {
    	try {
    		ldapBackEnd.setIdentityPassword(userName, domainName, password);
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    	}
    }

    @Override
    public String getAuthority()
    {
        return null;
    }
}
