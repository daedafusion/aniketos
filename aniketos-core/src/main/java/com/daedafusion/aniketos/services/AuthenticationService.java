package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.entities.AuthenticationResponse;
import com.daedafusion.aniketos.exceptions.IdentityLockedException;
import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.aniketos.exceptions.UnauthorizedException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Authentication;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.common.Callback;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.AuthenticationFailedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;
import com.daedafusion.security.identity.SubjectInspector;
import org.apache.log4j.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Created by mphilpot on 7/11/14.
 */
@Path("authenticate")
public class AuthenticationService
{
    private static final Logger log = Logger.getLogger(AuthenticationService.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Context
    private ServletConfig servletConfig;

    @POST
    @Path("certificate")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_JSON)
    public AuthenticationResponse authenticateCert(final String b64Cert)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            Authentication auth = framework.getService(Authentication.class);
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            SubjectInspector inspector = framework.getService(SubjectInspector.class);

            Subject subject = auth.login(new CallbackHandler()
            {
                @Override
                public void handle(Callback[] callbacks)
                {
                    for(Callback cb : callbacks)
                    {
                        switch (cb.getName())
                        {
                            case Callback.X509:
                                cb.setValue(b64Cert);
                                break;
                        }
                    }
                }
            });

            Token token = tokenExchange.exchange(subject);

            AuthenticationResponse response = new AuthenticationResponse();

            response.setToken(token.getTokenString());
            response.setMessage("Certificate Authenticate Successful");
            response.setDomain(inspector.getDomain(subject));

            return response;
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (AuthenticationFailedException e)
        {
            log.error("", e);
            throw new UnauthorizedException();
        }
        catch (AccountLockedException e)
        {
            log.error("", e);
            throw new IdentityLockedException(e.getMessage());
        }
        catch (PasswordResetRequiredException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.PasswordResetRequiredException(e.getMessage());
        }
        catch (PasswordQualityException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.PasswordQualityException( e.getMessage());
        }
    }

    @POST
    @Path("{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public AuthenticationResponse authenticate(@PathParam("username") final String username,
                                               @QueryParam("domain") final String domain,
                                               @HeaderParam("x-identity-password") final String password)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            Authentication auth = framework.getService(Authentication.class);
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            SubjectInspector inspector = framework.getService(SubjectInspector.class);

            Subject subject = auth.login(new CallbackHandler()
            {
                @Override
                public void handle(Callback[] callbacks)
                {
                    for(Callback cb : callbacks)
                    {
                        switch (cb.getName())
                        {
                            case Callback.USERNAME:
                                cb.setValue(username);
                                break;
                            case Callback.PASSWORD:
                                cb.setValue(password);
                                break;
                            case Callback.DOMAIN:
                                if(domain != null)
                                    cb.setValue(domain);
                                break;
                        }
                    }
                }
            });

            Token token = tokenExchange.exchange(subject);

            AuthenticationResponse response = new AuthenticationResponse();

            response.setToken(token.getTokenString());
            response.setMessage("Authenticate Successful");
            response.setDomain(inspector.getDomain(subject));

            return response;
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (AuthenticationFailedException e)
        {
            log.error("", e);
            throw new UnauthorizedException();
        }
        catch (AccountLockedException e)
        {
            log.error("", e);
            throw new IdentityLockedException(e.getMessage());
        }
        catch (PasswordResetRequiredException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.PasswordResetRequiredException(e.getMessage());
        }
        catch (PasswordQualityException e)
    	{
    		log.error("", e);
    		throw new com.daedafusion.aniketos.exceptions.PasswordQualityException( e.getMessage());
    	}
    }


    @POST
    @Path("reset/{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public AuthenticationResponse authenticateReset(@PathParam("username") final String username,
                                                    @QueryParam("domain") final String domain,
                                                    @HeaderParam("x-identity-password") final String password,
                                                    @HeaderParam("x-identity-oldpassword") final String oldPassword)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            Authentication auth = framework.getService(Authentication.class);
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            SubjectInspector inspector = framework.getService(SubjectInspector.class);

            Subject subject = auth.login(new CallbackHandler()
            {
                @Override
                public void handle(Callback[] callbacks)
                {
                    for (Callback cb : callbacks)
                    {
                        switch (cb.getName())
                        {
                            case Callback.USERNAME:
                                cb.setValue(username);
                                break;
                            case Callback.PASSWORD:
                                cb.setValue(password);
                                break;
                            case Callback.OLD_PASSWORD:
                                cb.setValue(oldPassword);
                                break;
                            case Callback.DOMAIN:
                                if (domain != null)
                                    cb.setValue(domain);
                                break;
                        }
                    }
                }
            });

            Token token = tokenExchange.exchange(subject);

            AuthenticationResponse response = new AuthenticationResponse();

            response.setToken(token.getTokenString());
            response.setMessage("Authenticate Successful");
            response.setDomain(inspector.getDomain(subject));

            return response;
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException(e.getMessage());
        }
        catch (AuthenticationFailedException e)
        {
            log.error("", e);
            throw new UnauthorizedException();
        }
        catch (AccountLockedException e)
        {
            log.error("", e);
            throw new IdentityLockedException(e.getMessage());
        }
        catch (PasswordQualityException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.PasswordQualityException(e.getMessage());
        }
        catch (PasswordResetRequiredException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.PasswordResetRequiredException(e.getMessage());
        }
    }
}
