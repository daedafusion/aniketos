package com.daedafusion.aniketos.services.admin;

import com.daedafusion.aniketos.exceptions.NotFoundException;
import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.admin.DomainAdmin;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.common.Domain;
import com.daedafusion.security.exceptions.*;
import org.apache.log4j.Logger;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
@Path("admin/domain")
public class DomainAdminService
{
    private static final Logger log = Logger.getLogger(DomainAdminService.class);

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void createDomain(@HeaderParam("authorization") String tokenString,
                             Domain domain)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            DomainAdmin admin = framework.getService(DomainAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.createDomain(subject, domain);
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
    @Consumes(MediaType.APPLICATION_JSON)
    public void updateDomain(@HeaderParam("authorization") String tokenString,
                             Domain domain)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            DomainAdmin admin = framework.getService(DomainAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.updateDomain(subject, domain);
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
            throw new NotFoundException();
        }
    }

    @DELETE
    @Path("{domain}")
    public void removeDomain(@HeaderParam("authorization") String tokenString,
                             @PathParam("domain") String domain)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            DomainAdmin admin = framework.getService(DomainAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            admin.removeDomain(subject, domain);
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
    @Produces(MediaType.APPLICATION_JSON)
    public List<Domain> listDomains(@HeaderParam("authorization") String tokenString)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            DomainAdmin admin = framework.getService(DomainAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return admin.listDomains(subject);
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
