package com.daedafusion.aniketos.framework.providers.token;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.admin.providers.SessionAdminProvider;
import com.daedafusion.security.common.Session;
import com.daedafusion.security.exceptions.NotFoundException;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class JWTSessionAdminProvider extends AbstractProvider implements SessionAdminProvider
{
    private static final Logger log = Logger.getLogger(JWTSessionAdminProvider.class);

    @Override
    public List<Session> getSessions()
    {
        return JWTStore.getInstance().getSessions();
    }

    @Override
    public void expireSession(String sessionId) throws NotFoundException
    {
        JWTStore.getInstance().expireSession(sessionId);
    }
}
