package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.exceptions.*;
import com.daedafusion.aniketos.exceptions.BadRequestException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.InvalidTokenException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import com.daedafusion.security.identity.IdentityStore;
import org.apache.log4j.Logger;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Created by mphilpot on 7/11/14.
 */
@Path("identity")
public class IdentityService
{
    private static final Logger log = Logger.getLogger(IdentityService.class);

    /**
     * TODO
     * This should probably be refactored into a generic query endpoint
     */
    @GET
    @Path("domain/{domain}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Identity> getIdentitiesForDomain(@HeaderParam("authorization") String tokenString,
                                                 @PathParam("domain") String domain)
    {
        ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

        TokenExchange tokenExchange = framework.getService(TokenExchange.class);
        IdentityStore identityStore = framework.getService(IdentityStore.class);

        try
        {
            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return identityStore.getIdentitiesForDomain(subject, domain);
        }
        catch (InvalidTokenException e)
        {
            log.error("", e);
            throw new BadRequestException("Invalid Token");
        }
        catch (UnauthorizedException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.UnauthorizedException();
        }
    }

    @GET
    @Path("self/{token}")
    @Produces(MediaType.APPLICATION_JSON)
    public Identity getIdentity(@PathParam("token") String tokenString)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityStore identityStore = framework.getService(IdentityStore.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return identityStore.getIdentity(subject);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (InvalidTokenException e)
        {
            log.error("", e);
            throw new BadRequestException("Invalid Token");
        }
    }

    @GET
    @Path("{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Identity getIdentity(@HeaderParam("authorization") String tokenString,
                                @QueryParam("domain") String domain,
                                @PathParam("username") String username)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityStore identityStore = framework.getService(IdentityStore.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return identityStore.getIdentity(subject, username, domain);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (UnauthorizedException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.UnauthorizedException();
        }
        catch (InvalidTokenException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.BadRequestException("Invalid Token");
        }
    }

    @POST
    @Path("password/{username}")
    public void setPassword(@HeaderParam("authorization") String tokenString,
                            @HeaderParam("x-identity-password") String password,
                            @QueryParam("domain") String domain,
                            @PathParam("username") String username)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityStore identityStore = framework.getService(IdentityStore.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            identityStore.setPassword(subject, username, domain, password);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (UnauthorizedException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.UnauthorizedException();
        }
        catch (InvalidTokenException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.BadRequestException("Invalid Token");
        }
    }

    @POST
    @Path("self/password/{token}")
    public void setPassword(@PathParam("token") String tokenString,
                            @HeaderParam("x-identity-password") String password)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityStore identityStore = framework.getService(IdentityStore.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            identityStore.setPassword(subject, password);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (InvalidTokenException e)
        {
            log.error("", e);
            throw new com.daedafusion.aniketos.exceptions.BadRequestException("Invalid Token");
        }
    }
}
