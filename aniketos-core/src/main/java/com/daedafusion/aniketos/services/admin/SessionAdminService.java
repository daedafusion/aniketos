package com.daedafusion.aniketos.services.admin;

import com.daedafusion.security.common.Session;
import org.apache.log4j.Logger;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */

@Path("admin/session")
public class SessionAdminService
{
    private static final Logger log = Logger.getLogger(SessionAdminService.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public List<Session> getSessions(@HeaderParam("authorization") String adminToken)
    {
        return null;
    }
}
