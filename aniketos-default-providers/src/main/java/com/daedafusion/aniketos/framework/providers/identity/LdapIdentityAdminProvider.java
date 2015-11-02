package com.daedafusion.aniketos.framework.providers.identity;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.admin.providers.IdentityAdminProvider;
import com.daedafusion.security.common.Capability;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.NotFoundException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class LdapIdentityAdminProvider extends AbstractProvider implements IdentityAdminProvider
{
    private static final Logger log = Logger.getLogger(LdapIdentityAdminProvider.class);

    // Get an instance to the Ldap backend singleton
    LdapIdentityBackend ldapBackEnd = LdapIdentityBackend.getInstance();

    @Override
    public Identity createIdentity(Identity identity)
    {
    	try {
    		return ldapBackEnd.createIdentity(identity);
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    		return null;
    	}
    }

    @Override
    public Identity updateIdentity(Identity identity) throws NotFoundException
    {
    	try {
    		return ldapBackEnd.updateIdentity(identity);
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
    		return null;
    	}
    }

    @Override
    public void removeIdentity(String userName, String domainName) throws NotFoundException
    {
    	try {
    		ldapBackEnd.deleteIdentity( userName, domainName );
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
    public List<Identity> listIdentitiesForDomain(String domainName)
    {
    	try {
    		return ldapBackEnd.getIdentitiesForDomain( domainName );
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    		return null;
    	}
    }

    @Override
    public List<Capability> listCapabilities()
    {
    	try {
    		return ldapBackEnd.getCapabilities();
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    		return null;
    	}

    }

    @Override
    public void addCapability(Capability capability)
    {
    	try {
    		ldapBackEnd.createCapability(capability);
    	}
    	catch( LdapIdentityBackendException e ) {
    		log.error( e );
    	}
    }

    @Override
    public void updateCapability(Capability capability) throws NotFoundException
    {
    	try {
    		ldapBackEnd.updateCapability(capability);
    	}
    	catch (LdapIdentityBackendException e) {
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
    public void deleteCapability(String capabilityName) throws NotFoundException
    {
    	try {
    		ldapBackEnd.deleteCapability(capabilityName);
    	}
    	catch(LdapIdentityBackendException e) {
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
}
