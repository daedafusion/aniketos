package com.daedafusion.aniketos.services.admin;

import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.admin.AuditAdmin;
import com.daedafusion.security.audit.AuditEvent;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.exceptions.InvalidTokenException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Created by mphilpot on 8/12/14.
 */
@Path("admin/audit")
public class AuditAdminService
{
    private static final Logger log = Logger.getLogger(AuditAdminService.class);

    @GET
    @Path("{after}/{before}/{limit}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<AuditEvent> getEvents(@HeaderParam("authorization") String tokenString,
                                      @PathParam("after") Long after,
                                      @PathParam("before") Long before,
                                      @PathParam("limit") Integer limit)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            AuditAdmin auditAdmin = framework.getService(AuditAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return auditAdmin.getEvents(subject, after, before, limit);
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
    @Path("username/{username}/{after}/{before}/{limit}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<AuditEvent> getEventsByUsername(@HeaderParam("authorization") String tokenString,
                                      @PathParam("username") String username,
                                      @PathParam("after") Long after,
                                      @PathParam("before") Long before,
                                      @PathParam("limit") Integer limit)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            AuditAdmin auditAdmin = framework.getService(AuditAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return auditAdmin.getEventsByUsername(subject, after, before, username, limit);
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
    @Path("source/{source}/{after}/{before}/{limit}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<AuditEvent> getEventsBySource(@HeaderParam("authorization") String tokenString,
                                                @PathParam("source") String source,
                                                @PathParam("after") Long after,
                                                @PathParam("before") Long before,
                                                @PathParam("limit") Integer limit)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);
            AuditAdmin auditAdmin = framework.getService(AuditAdmin.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            return auditAdmin.getEventsBySource(subject, after, before, source, limit);
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
