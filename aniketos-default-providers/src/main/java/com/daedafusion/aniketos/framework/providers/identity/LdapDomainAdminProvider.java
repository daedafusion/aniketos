package com.daedafusion.aniketos.framework.providers.identity;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.admin.providers.DomainAdminProvider;
import com.daedafusion.security.common.Domain;
import com.daedafusion.security.exceptions.NotFoundException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class LdapDomainAdminProvider extends AbstractProvider implements DomainAdminProvider
{
    private static final Logger log = Logger.getLogger(LdapDomainAdminProvider.class);

    // Get an instance to the Ldap backend singleton
    LdapIdentityBackend ldapBackEnd = LdapIdentityBackend.getInstance();

    @Override
    public void createDomain(Domain domainName)
    {
    	try {
    		ldapBackEnd.createDomain( domainName );
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    	}
    }

    @Override
    public void updateDomain(Domain domainName) throws NotFoundException
    {
    	try {
    		ldapBackEnd.updateDomain( domainName );
    	}
    	catch( LdapIdentityBackendException e ) {
			if (e.getCause() instanceof LdapOperationException)
				{
					LdapOperationException ldapOpExcept = (LdapOperationException) e.getCause();
					if ( ldapOpExcept.getResultCode() == ResultCodeEnum.NO_SUCH_OBJECT )
							throw new NotFoundException();
					else
						log.error(ldapOpExcept.getLocalizedMessage(), ldapOpExcept );
				}

    		log.error( e );
    	}
    }

    @Override
    public void removeDomain(String domainName) throws NotFoundException
    {
    	try {
    		ldapBackEnd.deleteDomain( domainName );
    	}
    	catch( LdapIdentityBackendException e ) {
			if (e.getCause() instanceof LdapOperationException)
				{
					LdapOperationException ldapOpExcept = (LdapOperationException) e.getCause();
					if ( ldapOpExcept.getResultCode() == ResultCodeEnum.NO_SUCH_OBJECT )
							throw new NotFoundException();
					else
						log.error(ldapOpExcept.getLocalizedMessage(), ldapOpExcept );
				}
			
    		log.error( e );
    	}
    }

    @Override
    public List<Domain> listDomains()
    {
    	try {
    		return ldapBackEnd.getAllDomains();
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    		return null;
    	}
    }
}
