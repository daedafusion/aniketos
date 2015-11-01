package com.daedafusion.aniketos;

import com.daedafusion.aniketos.services.*;
import com.daedafusion.aniketos.services.admin.DomainAdminService;
import com.daedafusion.aniketos.services.admin.IdentityAdminService;
import com.daedafusion.aniketos.services.admin.SessionAdminService;
import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;
import org.apache.log4j.Logger;
import org.glassfish.jersey.server.ResourceConfig;

/**
 * Created by mphilpot on 7/18/14.
 */
public class Application extends ResourceConfig
{
    private static final Logger log = Logger.getLogger(Application.class);

    public Application()
    {
        super(
                AuthenticationService.class,
                AuthorizationService.class,
                IdentityService.class,
                LogoutService.class,
                TokenService.class,
                DomainAdminService.class,
                IdentityAdminService.class,
                SessionAdminService.class,
                JacksonJsonProvider.class
        );
    }
}
