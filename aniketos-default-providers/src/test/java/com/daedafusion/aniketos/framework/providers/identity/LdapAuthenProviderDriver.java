package com.daedafusion.aniketos.framework.providers.identity;

import com.daedafusion.security.authentication.Authentication;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Callback;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.AuthenticationFailedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;
import com.daedafusion.sf.*;
import com.daedafusion.sf.config.ManagedObjectDescription;
import com.daedafusion.sf.config.ServiceConfiguration;
import com.daedafusion.sf.impl.DefaultServiceRegistry;
import org.apache.log4j.Logger;
import org.junit.Test;


public class LdapAuthenProviderDriver
{
    private static final Logger log = Logger.getLogger(LdapAuthenProviderDriver.class);

	static class TestCallbackHandler implements CallbackHandler
	{
		public void handle(Callback ... callbacks)
		{
			for ( Callback cb : callbacks )
			{
				if ( cb.getName().equals(Callback.USERNAME) )
				{
					cb.setValue("jcool");
				}
				else if (cb.getName().equals(Callback.DOMAIN) )
				{
					cb.setValue("test");
				}
				else if (cb.getName().equals(Callback.PASSWORD) )
				{
					cb.setValue("pleasechange");
				}
			}
		}
	}

	static class NoDomainCallbackHandler implements CallbackHandler
	{
		public void handle(Callback ... callbacks)
		{
			for ( Callback cb : callbacks )
			{
				if ( cb.getName().equals(Callback.USERNAME) )
				{
					cb.setValue("jcool@test");
				}
				else if (cb.getName().equals(Callback.PASSWORD) )
				{
					cb.setValue("pleasechange");
				}
			}
		}
	}

	static class BadPwdCallbackHandler implements CallbackHandler
	{
		public void handle(Callback ... callbacks)
		{
			for ( Callback cb : callbacks )
			{
				if ( cb.getName().equals(Callback.USERNAME) )
				{
					cb.setValue("jcool");
				}
				else if (cb.getName().equals(Callback.DOMAIN) )
				{
					cb.setValue("test");
				}
				else if (cb.getName().equals(Callback.PASSWORD) )
				{
					cb.setValue("badpassword");
				}
			}
		}
	}

	static class PwdResetCallbackHandler implements CallbackHandler
	{
		public void handle(Callback ... callbacks)
		{
			for ( Callback cb : callbacks )
			{
				if ( cb.getName().equals(Callback.USERNAME) )
				{
					cb.setValue("jcool");
				}
				else if (cb.getName().equals(Callback.DOMAIN) )
				{
					cb.setValue("test");
				}
				else if (cb.getName().equals(Callback.OLD_PASSWORD) )
				{
					cb.setValue("pleasechange");
				}
				else if (cb.getName().equals(Callback.PASSWORD) )
				{
					cb.setValue("changeme");
				}
			}
		}
	}

    @Test
	public static void main(String[] args) throws ServiceFrameworkException
		{
			System.setProperty("serviceFrameworkFactoryImpl", "com.daedafusion.sf.ServiceFrameworkTestFactory");

			ServiceFrameworkTestFactory factory = (ServiceFrameworkTestFactory) ServiceFrameworkFactory.getInstance();

			Subject subject = null;
			
	        // Construct manually

	        ServiceRegistry registry = new DefaultServiceRegistry();
	        registry.setServiceConfiguration(buildConfig());

			factory.setRegistry(registry);

			ServiceFramework sf = factory.getFramework();

	        // get the authentication service
	        Authentication authn = sf.getService(Authentication.class);

	        try
				{
					// login with known credentials
					subject = authn.login(new TestCallbackHandler() );
			        if (subject != null )
			        	authn.logoff(subject);
				} catch (AccountLockedException e)
				{
					log.info("Account Locked");
				} catch (PasswordResetRequiredException e)
				{
					log.info("Password Reset Required");
				} catch (PasswordQualityException e)
	        	{
	        		log.info("Illegal Password Quality");
	        	}
            catch (AuthenticationFailedException e)
            {
                log.info("Authentication Failed", e);
            }

            // Verify the subject
	        if (subject != null && !authn.verify(subject) )
	        	log.info("Bad Subject") ;
	        
	        try
	        	{
	    			// login with no domain specified and FQDN
			        subject = authn.login(new NoDomainCallbackHandler() );
			        if (subject != null )
			        	authn.logoff(subject);
				} catch (AccountLockedException e)
				{
					log.info("Account Locked");
				} catch (PasswordResetRequiredException e)
				{
					log.info("Password Reset Required");
				} catch (PasswordQualityException e)
	        	{
	        		log.info("Illegal Password Quality");
	        	}
            catch (AuthenticationFailedException e)
            {
                log.info("Authentication Failed", e);
            }


	        try
	        	{
	    			// login with bad credentials
			        subject = authn.login(new BadPwdCallbackHandler() );
			        if (subject != null )
			        	authn.logoff(subject);
				} catch (AccountLockedException e)
				{
					log.info("Account Locked");
				} catch (PasswordResetRequiredException e)
				{
					log.info("Password Reset Required");
				} catch (PasswordQualityException e)
	        	{
	        		log.info("Illegal Password Quality");
	        	}
            catch (AuthenticationFailedException e)
            {
                log.info("Authentication Failed", e);
            }

			try
				{
					// login and reset credentials
			        subject = authn.login(new PwdResetCallbackHandler() );
			        if (subject != null )
			        	authn.logoff(subject);
				} catch (AccountLockedException e)
				{
					log.info("Account Locked");
				} catch (PasswordResetRequiredException e)
				{
					log.info("Password Reset Required");
				} catch (PasswordQualityException e)
	        	{
	        		log.info("Illegal Password Quality");
	        	}
            catch (AuthenticationFailedException e)
            {
                log.info("Authentication Failed", e);
            }

	        // Stop the provider
			sf.stop();
		}

    private static ServiceConfiguration buildConfig()
    	{
    	    ServiceConfiguration config = new ServiceConfiguration();

            ManagedObjectDescription sd = new ManagedObjectDescription();
            sd.setImplClass("com.daedafusion.security.framework.authentication.AuthenticationImpl");
            sd.setInfClass("com.daedafusion.security.framework.authentication.Authentication");

            config.getManagedObjectDescriptions().add(sd);

    	    ManagedObjectDescription pd = new ManagedObjectDescription();
    	    pd.setImplClass("com.daedafusion.aniketos.framework.providers.authentication.LdapAuthenticationProvider");
    	    pd.setInfClass("com.daedafusion.security.framework.authentication.providers.AuthenticationProvider");

    	    config.getManagedObjectDescriptions().add(pd);

    	    config.compile();

    	    return config;
    	}
}



