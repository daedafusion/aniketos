package com.daedafusion.aniketos;

import com.daedafusion.aniketos.entities.AuthenticationResponse;
import com.daedafusion.aniketos.entities.TokenValidationResponse;
import com.daedafusion.aniketos.exceptions.AccountLockedException;
import com.daedafusion.aniketos.exceptions.InvalidTokenException;
import com.daedafusion.aniketos.exceptions.PasswordResetRequiredException;
import com.daedafusion.aniketos.exceptions.ServiceErrorException;
import com.daedafusion.security.common.Identity;
import org.apache.log4j.Logger;
import org.junit.Ignore;
import org.junit.Test;

import java.net.URISyntaxException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by mphilpot on 8/20/14.
 */
public class IntegrationDriver
{
    private static final Logger log = Logger.getLogger(IntegrationDriver.class);

    @Test
    @Ignore
    public void login() throws AccountLockedException, ServiceErrorException, PasswordResetRequiredException, URISyntaxException, InvalidTokenException
    {
        System.setProperty("etcdHost", "192.168.59.103");

        AniketosClient client = new AniketosClient(); // Use discovery

        AuthenticationResponse response = client.authenticate("bob", "test.com", "test");

        String token = response.getToken();

        log.info(token);

        assertThat(token, is(notNullValue()));

        Identity id = client.getIdentity(token);

        TokenValidationResponse tr = client.isTokenValid(token);

        assertThat(tr.getValid(), is(true));

        client.logout(token);
    }
}
