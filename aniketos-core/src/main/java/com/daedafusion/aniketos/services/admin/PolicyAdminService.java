package com.daedafusion.aniketos.services.admin;

import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.security.admin.PolicyAdmin;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.common.LockoutPolicy;
import com.daedafusion.security.common.PasswordPolicy;
import com.daedafusion.security.exceptions.InvalidTokenException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

/**
 * Created by mphilpot on 7/29/14.
 */
@Path("admin/policy")
public class PolicyAdminService
{
    private static final Logger log = Logger.getLogger(PolicyAdminService.class);

    @GET
    @Path("lockout/{domain}")
    @Produces(MediaType.APPLICATION_JSON)
    public LockoutPolicy getLockoutPolicy(@HeaderParam("authorization") String tokenString,
                                          @PathParam("domain") String domain)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            PolicyAdmin admin = framework.getService(PolicyAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.getLockoutPolicy(subject, domain);
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

    @GET
    @Path("password/{domain}")
    @Produces(MediaType.APPLICATION_JSON)
    public PasswordPolicy getPasswordPolicy(@HeaderParam("authorization") String tokenString,
                                            @PathParam("domain") String domain)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            PolicyAdmin admin = framework.getService(PolicyAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.getPasswordPolicy(subject, domain);
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
    @Path("lockout/{domain}")
    @Consumes(MediaType.APPLICATION_JSON)
    public void setLockoutPolicy(@HeaderParam("authorization") String tokenString,
                                  @PathParam("domain") String domain,
                                  LockoutPolicy policy)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            PolicyAdmin admin = framework.getService(PolicyAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.setLockoutPolicy(subject, domain, policy);
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
    @Path("password/{domain}")
    @Consumes(MediaType.APPLICATION_JSON)
    public void setPasswordPolicy(@HeaderParam("authorization") String tokenString,
                                 @PathParam("domain") String domain,
                                 PasswordPolicy policy)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            PolicyAdmin admin = framework.getService(PolicyAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.setPasswordPolicy(subject, domain, policy);
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
}
