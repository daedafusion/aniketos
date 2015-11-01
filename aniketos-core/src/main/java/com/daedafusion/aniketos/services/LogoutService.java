package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Authentication;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.exceptions.InvalidTokenException;
import org.apache.log4j.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;

/**
 * Created by mphilpot on 7/11/14.
 */
@Path("logout")
public class LogoutService
{
    private static final Logger log = Logger.getLogger(LogoutService.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Context
    private ServletConfig servletConfig;

    @POST
    @Path("{token}")
    public void logout(@PathParam("token") String tokenString)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            Authentication auth = framework.getService(Authentication.class);
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);

            Token token = tokenExchange.getToken(tokenString);

            Subject subject = tokenExchange.exchange(token);

            auth.logoff(subject);

            tokenExchange.destroyToken(token);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
        catch (InvalidTokenException e)
        {
            log.error(e.getMessage());
            throw new com.daedafusion.aniketos.exceptions.BadRequestException("Invalid Token");
        }
    }
}
