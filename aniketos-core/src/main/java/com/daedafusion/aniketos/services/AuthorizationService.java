package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.aniketos.framework.ServerAuthorization;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import org.apache.log4j.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Created by mphilpot on 7/11/14.
 */
@Path("authorization")
public class AuthorizationService
{
    private static final Logger log = Logger.getLogger(AuthorizationService.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Context
    private ServletConfig servletConfig;

    @POST
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_XML)
    public String evaluate(String request)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            ServerAuthorization auth = framework.getService(ServerAuthorization.class);

            return auth.evaluate(request);

        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
    }

//    @POST
//    @Consumes(MediaType.APPLICATION_JSON)
//    @Produces(MediaType.APPLICATION_JSON)
//    public org.oasis.xacml.json.Response evaluate(@HeaderParam("authorization") String tokenString,
//                                          org.oasis.xacml.json.Request request)
//    {
//        try
//        {
//            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();
//
//            ServerAuthorization auth = (ServerAuthorization) framework.getService(ServerAuthorization.URI);
//
//            // TODO Convert json to jaxb representation
//
//            return null;
//
//        }
//        catch (ServiceFrameworkException e)
//        {
//            log.error("", e);
//            throw new ServiceErrorException();
//        }
//    }

//    @POST
//    @Path("tree")
//    @Consumes(MediaType.APPLICATION_JSON)
//    @Produces(MediaType.APPLICATION_JSON)
//    public Response evaluateTree(@HeaderParam("authorization") String token,
//                                              Request request)
//    {
//        return null;
//    }
}
