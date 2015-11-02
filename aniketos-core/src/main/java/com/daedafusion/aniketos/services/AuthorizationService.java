package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.aniketos.framework.ServerAuthorization;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import org.apache.log4j.Logger;
import org.oasis.xacml.json.Request;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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
        ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

        ServerAuthorization auth = framework.getService(ServerAuthorization.class);

        return auth.evaluate(request);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public org.oasis.xacml.json.Response evaluate(@HeaderParam("authorization") String tokenString,
                                          org.oasis.xacml.json.Request request)
    {
        ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

        ServerAuthorization auth = (ServerAuthorization) framework.getService(ServerAuthorization.class);

        // TODO Convert json to jaxb representation

        throw new UnsupportedOperationException("Authentication XACML JSON Not Yet Supported");
    }

    @POST
    @Path("tree")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response evaluateTree(@HeaderParam("authorization") String token,
                                              Request request)
    {
        throw new UnsupportedOperationException("Authentication Tree Not Supported");
    }
}
