package com.daedafusion.aniketos.framework.providers.identity;

import com.daedafusion.aniketos.framework.providers.identity.LdapIdentityBackend.BindResult;
import com.daedafusion.security.common.*;
import com.daedafusion.security.common.PasswordPolicy.PasswordQualityCheck;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.util.*;


/**
 * Created by patrick on 7/24/14.
 */
public class LdapDriver
{
    private static final Logger log = Logger.getLogger(LdapDriver.class);


    public static void main(String[] args)
    {					
    	Boolean x;
    	int capCreates = 0;
    	int domainCreates = 0;
    	int policyCreates = 0;
    	int identityCreates = 0;

    	// Get an instance to the Ldap backend singleton
        LdapIdentityBackend ldapBackEnd = LdapIdentityBackend.getInstance();


		// Scenario testing
		int capCount = listCapabilities( ldapBackEnd );
		if ( getCapability( ldapBackEnd, "userCapability") == null )
			{
			createCapability( ldapBackEnd, "userCapability", "Defines the holder as a User");
			capCreates++;
			}
		if ( getCapability( ldapBackEnd, "testerCapability") == null )
			{
			createCapability( ldapBackEnd, "testerCapability", "Defined the holder as a Testor" );
			capCreates++;
			}
		if ( listCapabilities( ldapBackEnd ) == (capCount + capCreates) )
			{
				Capability capability = getCapability( ldapBackEnd, "testerCapability");
				if (capability != null )
					{
						// Seems updates that are identical causes the request to timeout
						if ( capCreates > 0 )
							{
								updateCapability( ldapBackEnd, "testerCapability", "Defines the holder as a Tester");
								capability = getCapability( ldapBackEnd, "CyberAnalyst"); 
								if ( capability != null )
									x = true;
							}
					}
			}
		
		int domainCount = listDomains( ldapBackEnd );
		if ( getDomain( ldapBackEnd, "GoldmanSachs") == null )
			{
			createDomain( ldapBackEnd, "GoldmanSachs");
			domainCreates++;
			}
		if ( (getDomain(ldapBackEnd, "GoldmanSachs") != null) && (getDomain(ldapBackEnd,"JPMorganChase") == null) )
			{
			createDomain( ldapBackEnd, "JPMorganChase");
			domainCreates++;
			}
		if ( (getDomain(ldapBackEnd, "JPMorganChase") != null) && (getDomain(ldapBackEnd, "BankOfAmerica") == null) )
			{
			createDomain( ldapBackEnd, "BankOfAmerica");
			domainCreates++;
			}
		if ( getDomain(ldapBackEnd, "BankOfAmerica") != null )
			{
			if ( listDomains( ldapBackEnd ) == (domainCount + domainCreates) )
				{
				Domain domain = getDomain( ldapBackEnd, "GoldmanSachs");
				if (domain != null )
					updateDomain( ldapBackEnd, "GoldmanSachs");
				}
			}
		
		if ( getPasswordPolicy( ldapBackEnd, null) != null )		// retrieve the global password policy
			if ( getLockoutPolicy( ldapBackEnd, null ) != null )	// retrieve the global lockout policy
				{
					if ( getPasswordPolicy( ldapBackEnd, "GoldmanSachs") == null )
						{
						createPasswordPolicy( ldapBackEnd, "GoldmanSachs");
						createLockoutPolicy( ldapBackEnd, "GoldmanSachs");
						if( getPasswordPolicy( ldapBackEnd, "GoldmanSachs") != null )
							if (getLockoutPolicy( ldapBackEnd, "GoldmanSachs" ) != null )
								{
									modifyPasswordPolicy( ldapBackEnd, "GoldmanSachs");
									modifyLockoutPolicy( ldapBackEnd, "GoldmanSachs");
									if (getPasswordPolicy( ldapBackEnd, "GoldmanSachs") != null )
										{
											if ( getPasswordPolicy( ldapBackEnd, "JPMorganChase" ) == null )
												createPasswordPolicy( ldapBackEnd, "JPMorganChase");
											if ( getPasswordPolicy( ldapBackEnd, "JPMorganChase") != null )
												x = true;
										}
								}
						}
				}

		int idCount = listIdentities( ldapBackEnd, null );
		if ( getIdentity( ldapBackEnd, "tester", "GoldmanSachs") == null )
			{
			createIdentity( ldapBackEnd, "tester", "GoldmanSachs", "Joe","Tester" );
			if ( getIdentity( ldapBackEnd, "tester", "GoldmanSachs") != null )
				setIdentityPassword( ldapBackEnd, "tester", "GoldmanSachs", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd, "tester" ,"GoldmanSachs") != null) && (getIdentity(ldapBackEnd, "tester", "BankOfAmerica") == null) )
			{
			createIdentity( ldapBackEnd, "tester", "BankOfAmerica", "Sam", "Tester" );
			if ( getIdentity( ldapBackEnd, "tester", "BankOfAmerica") != null )
				setIdentityPassword( ldapBackEnd, "tester", "BankOfAmerica", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd, "tester", "BankOfAmerica") != null) && (getIdentity(ldapBackEnd,"joebob", "BankOfAmerica") == null) )
			{
			createIdentity( ldapBackEnd, "joebob", "BankOfAmerica", "JoeBob", "Smith" );
			if ( getIdentity( ldapBackEnd, "joebob", "BankOfAmerica") != null )
				setIdentityPassword( ldapBackEnd, "joebob", "BankOfAmerica", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd,"joebob", "BankOfAmerica") != null) && (getIdentity(ldapBackEnd, "jcool","JPMorganChase") == null) )
			{
			createIdentity( ldapBackEnd, "jcool", "JPMorganChase", "Joe", "Cool" );
			if ( getIdentity( ldapBackEnd, "jcool", "JPMorganChase") != null )
				setIdentityPassword( ldapBackEnd, "jcool", "JPMorganChase", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd, "jcool","JPMorganChase") != null) && (getIdentity(ldapBackEnd, "jsmith","JPMorganChase") == null) )
			{
			createIdentity( ldapBackEnd, "jsmith", "JPMorganChase", "John", "Smith" );
			if ( getIdentity( ldapBackEnd, "jsmith", "JPMorganChase") != null )
				setIdentityPassword( ldapBackEnd, "jsmith", "JPMorganChase", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd, "jsmith","JPMorganChase") != null) && (getIdentity(ldapBackEnd, "jsomebody", "JPMorganChase") == null) )
			{
			createIdentity( ldapBackEnd, "jsomebody", "JPMorganChase", "Jay", "Sombody" );
			if ( getIdentity( ldapBackEnd, "jsomebody", "JPMorganChase") != null )
				setIdentityPassword( ldapBackEnd, "jsomebody", "JPMorganChase", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd, "jsomebody", "JPMorganChase") != null) && (getIdentity(ldapBackEnd, "pdiddy", "JPMorganChase") == null) )
			{
			createIdentity( ldapBackEnd, "pdiddy", "JPMorganChase", "P", "Diddy" );
			if ( getIdentity( ldapBackEnd, "pdiddy", "JPMorganChase") != null )
				setIdentityPassword( ldapBackEnd, "pdiddy", "JPMorganChase", "changeme");
			identityCreates++;
			}
		if ( (getIdentity(ldapBackEnd, "pdiddy", "JPMorganChase") != null) && (listIdentities( ldapBackEnd, null ) == (idCount + identityCreates) ) )
			{
				if (listIdentities( ldapBackEnd, "GoldmanSachs") == 1 )
					{
					if (listIdentities(ldapBackEnd, "BankOfAmerica") == 2 )
						{
						if (listIdentities( ldapBackEnd, "JPMorganChase") == 4 )
							{
								if ( bindSuccessful( ldapBackEnd, "tester", "GoldmanSachs", "aniketos") == BindResult.INVALID_CREDENTIALS)
									if ( bindSuccessful( ldapBackEnd, "tester", "GoldmanSachs", "changeme") == BindResult.CHANGE_AFTER_RESET )
										if (bindWithPasswordReset( ldapBackEnd, "tester", "GoldmanSachs", "changeme", "pleasechange") == BindResult.SUCCESS )
											listIdentities( ldapBackEnd, null );
								
								disableIdentity( ldapBackEnd, "tester", "GoldmanSachs");
								if (bindSuccessful( ldapBackEnd, "tester", "GoldmanSachs", "pleasechange") == BindResult.ACCOUNT_LOCKED )
									enableIdentity( ldapBackEnd, "tester", "GoldmanSachs");
								if (bindSuccessful( ldapBackEnd, "tester", "GoldmanSachs", "pleasechange") == BindResult.SUCCESS )
									listIdentities( ldapBackEnd, null );
								
								if ( !isPasswordExpired( ldapBackEnd, "tester", "GoldmanSachs") )
									expirePassword(ldapBackEnd, "tester", "GoldmanSachs");
								if ( isPasswordExpired(ldapBackEnd, "tester", "GoldmanSachs") )
									if ( setIdentityPassword( ldapBackEnd, "tester", "GoldmanSachs", "pleasechange") == BindResult.PASSWORD_IN_HISTORY )
										listIdentities( ldapBackEnd, null );
							}
						}
					}
					
		        if ( getIdentity(ldapBackEnd, "pdiddy", "JPMorganChase") != null )
		        	{
		        		if ( !isPasswordExpired( ldapBackEnd, "pdiddy", "JPMorganChase") )
		        			expirePassword(ldapBackEnd, "pdiddy", "JPMorganChase");
		        		if ( isPasswordExpired(ldapBackEnd, "pdiddy", "JPMorganChase") )
							setIdentityPassword( ldapBackEnd, "pdiddy", "JPMorganChase", "pleasechange");
		        	}
			}

		// Cleanup
		if ( getIdentity(ldapBackEnd, "tester", "BankOfAmerica") != null )
			deleteIdentity( ldapBackEnd, "tester", "BankOfAmerica");
		if ( getIdentity(ldapBackEnd, "tester", "GoldmanSachs") != null )		
			deleteIdentity( ldapBackEnd, "tester", "GoldmanSachs");
		if ( getIdentity(ldapBackEnd, "jcool", "JPMorganChase") != null )
			deleteIdentity( ldapBackEnd, "jcool", "JPMorganChase");
		if ( getIdentity(ldapBackEnd, "jsmith", "JPMorganChase") != null )
			deleteIdentity( ldapBackEnd, "jsmith", "JPMorganChase");
		if ( getIdentity(ldapBackEnd, "jsomebody", "JPMorganChase") != null )
			deleteIdentity( ldapBackEnd, "jsomebody", "JPMorganChase");
		if ( getIdentity(ldapBackEnd, "pdiddy", "JPMorganChase") != null )
			deleteIdentity( ldapBackEnd, "pdiddy", "JPMorganChase");
		
//		if ( getPasswordPolicy( ldapBackEnd, "GoldmanSachs") != null)
//			deletePasswordPolicy( ldapBackEnd, "GoldmanSachs");
		if ( getPasswordPolicy( ldapBackEnd, "JPMorganChase") != null )
			deletePasswordPolicy( ldapBackEnd, "JPMorganChase");

		if ( getDomain( ldapBackEnd, "GoldmanSachs") != null )
			deleteDomain( ldapBackEnd, "GoldmanSachs");
		if ( getDomain( ldapBackEnd, "JPMorganChase") != null )
			deleteDomain( ldapBackEnd, "JPMorganChase");
		if ( getDomain( ldapBackEnd, "BankOfAmerica") != null )
			deleteDomain( ldapBackEnd, "BankofAmerica");

		if ( getCapability( ldapBackEnd, "testerCapability") != null )
			deleteCapability( ldapBackEnd, "testerCapability");
		if ( getCapability( ldapBackEnd, "userCapability") != null )
			deleteCapability( ldapBackEnd, "userCapability");


    }

    /**
     * bindSuccessful - Test the ability to bind to an existing identity as a means of testing authentication
     * 
     * @param backEnd
     */
	@Test
	public static BindResult bindSuccessful( LdapIdentityBackend backEnd, String username, String domainName, String password)
	{
		try {
			return backEnd.bind(username, domainName, password);
		}
		catch (LdapIdentityBackendException e)
			{
				e.printStackTrace();
				return BindResult.FAILURE;
			}
	}
	
	/**
	 * bindWithPasswordReset - Test the ability for a user to change their password
	 * 
	 * @param backEnd
	 */
	@Test
	public static BindResult bindWithPasswordReset( LdapIdentityBackend backEnd, String username, String domainName, String oldPassword, String newPassword)
	{
		try {
			return backEnd.bindAndReset(username, domainName, oldPassword, newPassword );
		}
		catch( LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return BindResult.FAILURE;
			}
	}
	
	/**
	 * getIdentity - Test to retrieves the details for the identity specified by username and domain
	 * 
	 * @param backEnd
	 * @param username
	 * @param domain
	 * @throws LdapIdentityBackendException
	 */
	@Test
	public static Identity getIdentity( LdapIdentityBackend backEnd, String username, String domain)
	{
		Identity identity = null;
		String user, domainName;
		String[] values;
		int len;

		try {
				identity = backEnd.getIdentity( username, domain );
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return null;
			}
		
		if ( identity != null )
			{
				domainName = identity.getDomain();
				user = identity.getUsername();
				
				Map<String, Set<String>>attributes = identity.getAttributes();
				for ( String key : attributes.keySet() )
					{
					values = attributes.get(key).toArray(new String[0]);
					if ( values != null )
						{
							len = values.length;
						}
					}				
			}
		
		return identity;
	}
	
	/**
	 * listIdentities - Test to retrieves a list of all Identities within the specified domain or all domains
	 * 
	 * @param backEnd
	 * @param domain
	 * @throws LdapIdentityBackendException
	 */
	@Test
	public static int listIdentities( LdapIdentityBackend backEnd, String domain)
	{
		List<Identity> identities = null;
		String username, domainName;
		String[] values;
		int len;

		try {
		if (domain != null )
			identities = backEnd.getIdentitiesForDomain(domain);
		else
			identities = backEnd.getAllIdentities();
		}
		catch ( LdapIdentityBackendException e )
			{
				
			}
		
		if (identities != null )
			{
				boolean empty = identities.isEmpty();
				int size = identities.size();

				Map<String, Set<String>> attributes;
				for (Identity identity : identities )
					{
						domainName = identity.getDomain();
						username = identity.getUsername();
						
						attributes = identity.getAttributes();
    					for ( String key : attributes.keySet() )
    						{
    						values = attributes.get(key).toArray(new String[0]);
    						if ( values != null )
    							{
    								len = values.length;
    							}
    						}
					}
			}
		
		return identities.size();
	}

	
	/**
	 * createIdentity - Test to create an identity
	 * 
	 * @param backEnd
	 * @param username
	 * @param domain
	 */
	@Test
	public static void createIdentity( LdapIdentityBackend backEnd, String username, String domain, String firstName, String lastName )
	{
		Identity identity = new Identity();
		
		Map<String, Set<String>> attributes = new HashMap<String, Set<String>>();
		
		attributes.put(Identity.ATTR_FULLNAME, Collections.singleton(username));
		attributes.put(Identity.ATTR_FIRSTNAME, Collections.singleton(firstName));
		attributes.put(Identity.ATTR_LASTNAME, Collections.singleton(lastName));
		attributes.put(Identity.ATTR_MAIL, Collections.singleton(username + "@" + domain + ".com"));
		attributes.put(Identity.ATTR_AUTHENTICATOR_KEY, Collections.singleton("12345"));
		attributes.put(Identity.ATTR_CAPABILITIES, Collections.singleton("CyberAnalyst"));
		
		identity.setDomain(domain);
		identity.setUsername(username);
		identity.setAttributes(attributes);
		
		try
			{
				backEnd.createIdentity( identity );
			}
		catch ( LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}		
	}
	
	
	/**
	 * updateIdentity - Test to update an existing identity with new attributes or description
	 * 
	 * @param backEnd
	 * @param username
	 * @param domain
	 */
	@Test
	public static void updateIdentity( LdapIdentityBackend backEnd, String username, String domain  )
	{
		Map<String, Set<String>> attributes = new HashMap<String, Set<String>>();
		attributes.put(Identity.ATTR_DESCRIPTION, Collections.singleton("Cyber Analysts for Perspectus Department" ));
		attributes.put(Identity.ATTR_TELEPHONE_NUMBER, Collections.singleton("1-212-902-1171") );
		attributes.put(Identity.ATTR_LOCALITY, Collections.singleton("Jersey City") );
		attributes.put(Identity.ATTR_POSTAL_ADDRESS, Collections.singleton("100 Burma Road") );
		attributes.put(Identity.ATTR_POSTAL_CODE, Collections.singleton("07305") );
		attributes.put(Identity.ATTR_STATE_PROVINCE, Collections.singleton("NJ") );
		attributes.put(Identity.ATTR_MAIL, Collections.singleton("gs-investor-relations@gs.com") );
		
		Set<String> capabilities = new HashSet<String>();
		capabilities.add("cyberAnalyst");
		capabilities.add("domainAdmin");
		attributes.put(Identity.ATTR_CAPABILITIES, capabilities );

		Identity identity = new Identity();
		identity.setUsername(username);
		identity.setDomain(domain);
		identity.setAttributes(attributes);

		try {
			backEnd.updateIdentity( identity );
		}
		catch( LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * deleteIdentity - Test to delete an existing identity
	 * @param backEnd
	 * @param username
	 * @param domain
	 */
	public static void deleteIdentity( LdapIdentityBackend backEnd, String username, String domain )
	{
		try {
			backEnd.deleteIdentity(username, domain);
		}
		catch( LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * setIdentityPassword - Test administrative reset of password
	 * 
	 * @param backEnd
	 * @param username
	 * @param domainName
	 * @param password
	 */
	@Test
	public static BindResult setIdentityPassword( LdapIdentityBackend backEnd, String username, String domainName, String password )
	{
		try {
			return backEnd.setIdentityPassword(username, domainName, password);
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return BindResult.FAILURE;
			}
	}
	
	/**
	 * listDomains - Test to list all the domains
	 * 
	 * @param backEnd
	 */
	@Test
	public static int  listDomains( LdapIdentityBackend backEnd )
	{
		try
			{
				List<String> domains = backEnd.listAllDomains();
				int size = domains.size();
				for ( String domain : domains )
					;
			
				return domains.size();
			}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return -1;
			}
	}
	
	/**
	 * getDomain - Test to get details about a specified domain
	 * 
	 * @param backEnd
	 * @param domainName
	 * @throws LdapIdentityBackendException
	 */
	@Test
	public static Domain getDomain( LdapIdentityBackend backEnd, String domainName)
	{
		Domain domain = null;
		String domainNameStr;
		String description;
		String[] values;
		int len;

		try {
				domain = backEnd.getDomain( domainName );
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return null;
			}
		
		if ( domain != null )
			{
				if (domain.getDomainName().equals(domainName) )
					description = domain.getDescription();
				else
					return null;
				
				Map<String, Set<String>>attributes = domain.getAttributes();
				for ( String key : attributes.keySet() )
					{
					values = attributes.get(key).toArray(new String[0]);
					if ( values != null )
						{
							len = values.length;
						}
					}				
			}
		
		return domain;
	}

	/**
	 * createDomain - Test to create a new domain
	 * 
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void createDomain( LdapIdentityBackend backEnd, String domainName )
	{
		Map<String, Set<String>> attributes = new HashMap<String, Set<String>>();
		attributes.put(Domain.ATTR_FAX, Collections.singleton("+1 (123) 123-4567") );
		attributes.put(Domain.ATTR_TELEPHONE_NUMBER, Collections.singleton("1-212-902-0300") );
		attributes.put(Domain.ATTR_LOCALITY, Collections.singleton("New York") );
		attributes.put(Domain.ATTR_POSTAL_ADDRESS, Collections.singleton("200 West Street, 29th Floor") );
		attributes.put(Domain.ATTR_POSTAL_CODE, Collections.singleton("10282") );
		attributes.put(Domain.ATTR_STATE_PROVINCE, Collections.singleton("NY") );

		Domain domain = new Domain();
		domain.setDomainName(domainName);
		domain.setDescription(domainName + " Investment Relations");
		domain.setAttributes(attributes);
		
		try {
			backEnd.createDomain( domain );
		}
		catch( LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}		
	}
	
	/**
	 * updateDomain - Test to update an existing domain with new attributes or description
	 * 
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void updateDomain( LdapIdentityBackend backEnd, String domainName )
	{
		Map<String, Set<String>> attributes = new HashMap<String, Set<String>>();
		attributes.put(Domain.ATTR_TELEPHONE_NUMBER, Collections.singleton("1-212-902-1171") );
		attributes.put(Domain.ATTR_LOCALITY, Collections.singleton("Jersey City") );
		attributes.put(Domain.ATTR_POSTAL_ADDRESS, Collections.singleton("100 Burma Road") );
		attributes.put(Domain.ATTR_POSTAL_CODE, Collections.singleton("07305") );
		attributes.put(Domain.ATTR_STATE_PROVINCE, Collections.singleton("NJ") );

		Domain domain = new Domain();
		domain.setDomainName(domainName);
		domain.setDescription(domainName + " Prospectus Department");
		domain.setAttributes(attributes);
		
		try {
			backEnd.updateDomain( domain );
		}
		catch( LdapIdentityBackendException e )
			{
				String msg;
				if ( (msg = e.getLocalizedMessage()) == null )
					msg = e.getMessage();
				
				if (e.getCause() instanceof LdapOperationException)
					{
						LdapOperationException ldapOpExcept = (LdapOperationException) e.getCause();
						if ( ldapOpExcept.getResultCode() == ResultCodeEnum.NO_SUCH_OBJECT )
							{
								log.error(ldapOpExcept.getLocalizedMessage(), ldapOpExcept );
							}
					}
				else
					e.printStackTrace();
			}
	}
	
	/**
	 * deleteDomain - Test to delete an existing domain
	 * 
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void deleteDomain( LdapIdentityBackend backEnd, String domainName )
	{
		try {
			backEnd.deleteDomain(domainName);
		}
		catch( LdapIdentityBackendException e )
			{
				String msg;
				if ( (msg = e.getLocalizedMessage()) == null )
					msg = e.getMessage();
				
				if (e.getCause() instanceof LdapOperationException)
					{
						LdapOperationException ldapOpExcept = (LdapOperationException) e.getCause();
						if ( ldapOpExcept.getResultCode() == ResultCodeEnum.NO_SUCH_OBJECT )
							{
								log.error(ldapOpExcept.getLocalizedMessage(), ldapOpExcept );
							}
					}
				else
					e.printStackTrace();
			}
	}
	
	/**
	 * listCapabilities - Test to retrieve a list of the Capabilities
	 * 
	 * @param backEnd
	 */
	@Test
	public static int listCapabilities( LdapIdentityBackend backEnd )
	{
		try
			{
				List<String> capabilities = backEnd.listCapabilities();
				int size = capabilities.size();
				for ( String capability : capabilities )
					;
				return capabilities.size();
			}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return -1;
			}
	}
	
	/**
	 * getCapability - Test to retrieve details about a specific Capability
	 * 
	 * @param backEnd
	 * @param capabilityName
	 * @throws LdapIdentityBackendException
	 */
	@Test
	public static Capability getCapability( LdapIdentityBackend backEnd, String capabilityName)
	{
		Capability capability = null;
		String capabilityNameStr;
		String description;
		String[] values;
		int len;

		try {
				capability = backEnd.getCapability( capabilityName );
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
				return null;
			}
		
		if ( capability != null )
			{
				capabilityNameStr = capability.getCapabilityName();
				description = capability.getDescription();
				
				Map<String, Set<String>>attributes = capability.getAttributes();
				for ( String key : attributes.keySet() )
					{
					values = attributes.get(key).toArray(new String[0]);
					if ( values != null )
						{
							len = values.length;
						}
					}				
			}
		
		return capability;
	}

	/**
	 * createCapability - creates a Capability entry
	 * 
	 * @param backEnd
	 * @param capabilityName
	 * @param description
	 */
	@Test
	public static void createCapability( LdapIdentityBackend backEnd, String capabilityName, String description )
	{
		Capability capability = new Capability();
		
		capability.setCapabilityName(capabilityName);
		capability.setDescription(description);
		try{
			backEnd.createCapability(capability);
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * updateCapability - Updates an existing Capability
	 * 
	 * @param backEnd
	 * @param capabilityName
	 * @param description
	 */
	@Test
	public static void updateCapability( LdapIdentityBackend backEnd, String capabilityName, String description )
	{
		Capability capability = new Capability();
		
		capability.setCapabilityName(capabilityName);
		capability.setDescription(description);
		try{
			backEnd.updateCapability(capability);
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}	

	/**
	 * deleteCapability - Deletes an existing Capability 
	 * 
	 * @param backEnd
	 * @param capabilityName
	 */
	@Test
	public static void deleteCapability( LdapIdentityBackend backEnd, String capabilityName )
	{
		try{
			backEnd.deleteCapability(capabilityName);
		}
		catch (LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * enableIdentity -		Enables a previously disabled identity
	 * 
	 * @param backEnd
	 * @param username
	 * @param domainName
	 */
	@Test
	public static void enableIdentity( LdapIdentityBackend backEnd, String username, String domainName )
	{
		try {
			backEnd.enableIdentity( username, domainName );
		}
		catch( LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}

	/**
	 * disableIdentity -		Disable an identity
	 * 
	 * @param backEnd
	 * @param username
	 * @param domainName
	 */
	@Test
	public static void disableIdentity( LdapIdentityBackend backEnd, String username, String domainName )
	{
		try {
			backEnd.disableIdentity( username, domainName );
		}
		catch( LdapIdentityBackendException e )
			{
				e.printStackTrace();
			}
	}

	/**
	 * getPasswordPolicy	-	Test the retrieval of the password policy for a specific domain
	 * 							or the global password policy
	 * 
	 * @param backEnd
	 */
	@Test
	public static PasswordPolicy getPasswordPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		PasswordPolicy pwdPolicy;
		
		try {
				pwdPolicy = backEnd.getPasswordPolicy(domainName);
		}
		catch( Exception e )
			{
				e.printStackTrace();
				return null;
			}
		
		return pwdPolicy;
	}

	/**
	 * getLockoutPolicy	-	Test the retrieval of the lockout polic for a specific domain
	 * 						or the global lockout policy
	 * 
	 * @param backEnd
	 */
	@Test
	public static LockoutPolicy getLockoutPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		LockoutPolicy policy;
		
		try {
				policy = backEnd.getLockoutPolicy(domainName);
		}
		catch( Exception e )
			{
				e.printStackTrace();
				return null;
			}
		
		return policy;
	}
	
	/**
	 * createPasswordPolicy - Tests the ability to create a Password Policy
	 *  
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void createPasswordPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		PasswordPolicy policy = new PasswordPolicy();
		
		policy.setPolicyEnabled(true);
		policy.setMinLength(8);
		policy.setExpireWarning(600L);
		policy.setGraceAuthnLimit(5);
		policy.setQualityCheckLevel(PasswordQualityCheck.RELAXED);
		policy.setMustChange(true);
		policy.setAllowUserChange(true);
		
		try {
			backEnd.setPasswordPolicy(domainName, policy);
		}
		catch ( LdapIdentityBackendException e)
			{
				String msg;
				if ( (msg = e.getLocalizedMessage()) == null )
					msg = e.getMessage();
				
				if (e.getCause() instanceof LdapOperationException)
					{
						LdapOperationException ldapOpExcept = (LdapOperationException) e.getCause();
						if ( ldapOpExcept.getResultCode() == ResultCodeEnum.NO_SUCH_OBJECT )
							{
								log.error(ldapOpExcept.getLocalizedMessage(), ldapOpExcept );
							}
					}
				else
					e.printStackTrace();
			}
	}
	
	/**
	 * modifyPasswordPolicy - Tests the ability to modify a Password Policy
	 *  
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void modifyPasswordPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		PasswordPolicy policy = new PasswordPolicy();
		
		policy.setPolicyEnabled(true);
		policy.setMinLength(5);
		policy.setExpireWarning(1200L);
		policy.setGraceAuthnLimit(2);
		policy.setQualityCheckLevel(PasswordQualityCheck.RELAXED);
		policy.setMustChange(false);
		policy.setAllowUserChange(true);
		
		try {
			backEnd.setPasswordPolicy(domainName, policy);
		}
		catch ( Exception e)
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * createLockoutPolicy - Tests the ability to create a Lockout Policy
	 *  
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void createLockoutPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		LockoutPolicy policy = new LockoutPolicy();
		
		policy.setPolicyEnabled(true);
		policy.setFailureCountInterval(30L);
		policy.setLockoutDuration(10L);
		policy.setMaxAttempts(10);
		policy.setMaxIdle(2592000L);
		policy.setPasswordsInHistory(10);
		
		try {
			backEnd.setLockoutPolicy(domainName, policy);
		}
		catch ( Exception e)
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * modifyLockoutPolicy - Tests the ability to modify a Lockout Policy
	 *  
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void modifyLockoutPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		LockoutPolicy policy = new LockoutPolicy();
		
		policy.setPolicyEnabled(true);
		policy.setFailureCountInterval(30L);
		policy.setLockoutDuration(0L);
		policy.setMaxAttempts(5);
		policy.setMaxIdle(2592000L);
		policy.setPasswordsInHistory(5);

		try {
			backEnd.setLockoutPolicy(domainName, policy);
		}
		catch ( Exception e)
			{
				e.printStackTrace();
			}
	}
	
	/**
	 * deletePasswordPolicy -	Tests the ability to delete a named lockout and password
	 * 							policy
	 * @param backEnd
	 * @param domainName
	 */
	@Test
	public static void deletePasswordPolicy( LdapIdentityBackend backEnd, String domainName )
	{
		try {
			backEnd.deletePasswordPolicy(domainName);
		}
		catch( Exception e )
			{
				e.printStackTrace();
			}
	}
	
	
	/**
	 * Test of ability to expire the password of a specified user
	 * 
	 * @param backEnd
	 * @param username
	 * @param domainName
	 */
	@Test
	public static void expirePassword( LdapIdentityBackend backEnd, String username, String domainName )
	{
		try {
			backEnd.expirePassword(username, domainName);
		}
		catch( Exception e )
			{
				e.printStackTrace();
			}
	}
	
	@Test
	public static boolean isPasswordExpired( LdapIdentityBackend backEnd, String username, String domainName )
	{
		try {
			return backEnd.isPasswordExpired(username, domainName);
		}
		catch( Exception e )
			{
				e.printStackTrace();
				return false;
			}
	}
}
