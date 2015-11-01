package com.daedafusion.aniketos.framework.impl;

import com.daedafusion.aniketos.framework.ServerAuthorization;
import com.daedafusion.aniketos.framework.providers.ServerAuthorizationProvider;
import com.daedafusion.sf.AbstractService;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/21/14.
 */
public class ServerAuthorizationImpl extends AbstractService<ServerAuthorizationProvider> implements ServerAuthorization
{
    private static final Logger log = Logger.getLogger(ServerAuthorizationImpl.class);

    @Override
    public String evaluate(String request)
    {
        return getSingleProvider().evaluate(request);
    }

    @Override
    public Class getProviderInterface()
    {
        return ServerAuthorizationProvider.class;
    }
}
