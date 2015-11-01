package com.daedafusion.aniketos.services.admin;

import com.daedafusion.aniketos.exceptions.NotFoundException;
import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.admin.IdentityAdmin;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.common.Capability;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.*;
import org.apache.log4j.Logger;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
@Path("admin/identity")
public class IdentityAdminService
{
    private static final Logger log = Logger.getLogger(IdentityAdminService.class);

    @GET
    @Path("{domain}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Identity> listIdentitiesForDomain(@HeaderParam("authorization") String tokenString,
                                                  @PathParam("domain") String domain)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.listIdentitiesForDomain(subject, domain);
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
    @Path("{domain}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Identity createIdentity(@HeaderParam("authorization") String tokenString,
                                   @PathParam("domain") String domain,
                                   Identity identity)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.createIdentity(subject, identity);
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

    @PUT
    @Path("{domain}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Identity updateIdentity(@HeaderParam("authorization") String tokenString,
                                   @PathParam("domain") String domain,
                                   Identity identity)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.updateIdentity(subject, identity);
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
        catch (com.daedafusion.security.exceptions.NotFoundException e)
        {
            log.error("", e);
            throw new NotFoundException(e.getMessage());
        }
    }


    @DELETE
    @Path("{domain}/{user}")
    public void removeIdentity(@HeaderParam("authorization") String tokenString,
                               @PathParam("domain") String domain,
                               @PathParam("user") String user)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.removeIdentity(subject, user, domain);
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
        catch (com.daedafusion.security.exceptions.NotFoundException e)
        {
            log.error("", e);
            throw new NotFoundException(e.getMessage());
        }
    }

    @GET
    @Path("capabilities")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Capability> getCapabilities(@HeaderParam("authorization") String tokenString)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.listCapabilities(subject);
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
    @Path("capabilities")
    @Consumes(MediaType.APPLICATION_JSON)
    public void addCapability(@HeaderParam("authorization") String tokenString,
                              Capability capability)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.addCapability(subject, capability);
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

    @PUT
    @Path("capabilities")
    @Consumes(MediaType.APPLICATION_JSON)
    public void updateCapability(@HeaderParam("authorization") String tokenString,
                              Capability capability)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.updateCapability(subject, capability);
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
        catch (com.daedafusion.security.exceptions.NotFoundException e)
        {
            log.error("", e);
            throw new NotFoundException(e.getMessage());
        }
    }

    @DELETE
    @Path("capabilities")
    public void deleteCapability(@HeaderParam("authorization") String tokenString,
                                 @HeaderParam("x-identity-capability") String capability)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            IdentityAdmin admin = framework.getService(IdentityAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.deleteCapability(subject, capability);
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
        catch (com.daedafusion.security.exceptions.NotFoundException e)
        {
            log.error("", e);
            throw new NotFoundException(e.getMessage());
        }
    }
}
