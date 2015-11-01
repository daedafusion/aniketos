package com.daedafusion.aniketos.services;

import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.audit.Audit;
import com.daedafusion.security.audit.AuditEvent;
import org.apache.log4j.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;

/**
 * Created by mphilpot on 8/12/14.
 */
@Path("audit")
public class AuditService
{
    private static final Logger log = Logger.getLogger(AuditService.class);

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void reportEvent(AuditEvent event)
    {
        try
        {
            ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

            Audit audit = framework.getService(Audit.class);

            audit.reportEvent(event);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("", e);
            throw new ServiceErrorException();
        }
    }
}
