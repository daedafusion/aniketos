package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.entities.TokenValidationResponse;
import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.aniketos.framework.ServerTokenExchange;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.*;
import com.daedafusion.security.exceptions.InvalidTokenException;
import org.apache.log4j.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Created by mphilpot on 7/11/14.
 */
@Path("token")
public class TokenService
{
    private static final Logger log = Logger.getLogger(TokenService.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Context
    private ServletConfig servletConfig;

    @POST
    @Path("{token}")
    @Produces(MediaType.APPLICATION_JSON)
    public TokenValidationResponse isTokenValid(@PathParam("token") String tokenString)
                                                //@QueryParam("pingSession") @DefaultValue("true") String pingSession)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            TokenExchange tokenExchange = framework.getService(TokenExchange.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            TokenValidationResponse response = new TokenValidationResponse();

            if(tokenExchange.isTokenValid(token))
            {
                response.setUser(subject.getAttributes(Principal.PRINCIPAL_NAME).iterator().next());
                response.setDomain(subject.getAttributes(Principal.PRINCIPAL_DOMAIN).iterator().next());
                response.setValid(true);
            }
            else
            {
                response.setValid(false);
            }

            return response;
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (InvalidTokenException e)
        {
            TokenValidationResponse response = new TokenValidationResponse();
            response.setValid(false);

            return response;
        }
    }

    @POST
    @Path("{token}/noping")
    @Produces(MediaType.APPLICATION_JSON)
    public TokenValidationResponse isTokenValidNoSession(@PathParam("token") String token)
    {
        ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

        ServerTokenExchange tokenExchange = framework.getService(ServerTokenExchange.class);

        TokenValidationResponse response = new TokenValidationResponse();

        if(tokenExchange.isTokenValidNoSession(token))
        {
            response.setValid(true);
        }
        else
        {
            response.setValid(false);
        }

        return response;
    }
}
