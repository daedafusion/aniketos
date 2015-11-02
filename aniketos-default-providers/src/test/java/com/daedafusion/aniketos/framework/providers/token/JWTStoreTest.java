package com.daedafusion.aniketos.framework.providers.token;

import com.daedafusion.security.common.Session;
import com.daedafusion.security.exceptions.NotFoundException;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;

/**
 * Created by mphilpot on 4/2/15.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JWTStoreTest
{
    private static final Logger log = Logger.getLogger(JWTStoreTest.class);
    private final JWTStore store;

    public JWTStoreTest()
    {
        System.setProperty("jwt.hmacSharedSecret", "qrllxoyy2x2bnsp84yjoi5wujrnqun6y0lspeu28");
        this.store = JWTStore.getInstance();
    }

    @Test
    public void test0init()
    {
        assertThat(store.getSessions().isEmpty(), is(true));
        assertThat(store.isValidToken("asdf", true), is(false));
        assertThat(store.getIdentityForToken("asdf"), is(nullValue()));

        // These shouldn't throw anything
        store.destroyToken("asdf");
    }

    @Test(expected = NotFoundException.class)
    public void test0notFound() throws NotFoundException
    {
        store.expireSession("asdf");
    }

    @Test
    public void test1create()
    {
        long now = System.currentTimeMillis();
        String token = store.newToken("test@domain.com", "domain.com");

        assertThat(token, is(notNullValue()));
        assertThat(token.length(), is(not(0)));
        assertThat(store.getSessions().size(), is(1));

        Session s = store.getSessions().get(0);

        assertThat(s.getId(), is(notNullValue()));
        assertThat(s.getDomain(), is("domain.com"));
        assertThat(s.getToken(), is(token));
        assertThat(s.getUser(), is("test@domain.com"));
        assertThat(s.getSessionStart(), is(greaterThan(now)));
        assertThat(s.getSessionExpiration(), is(greaterThan(s.getSessionStart())));
    }

    @Test
    public void test2ping() throws InterruptedException
    {
        long lastActive = store.getSessions().get(0).getLastActive();

        assertThat(store.isValidToken(store.getSessions().get(0).getToken(), false), is(true));

        assertThat(store.getSessions().get(0).getLastActive(), is(lastActive));

        TimeUnit.MILLISECONDS.sleep(100);

        assertThat(store.isValidToken(store.getSessions().get(0).getToken(), true), is(true));

        assertThat(store.getSessions().get(0).getLastActive(), is(greaterThan(lastActive)));
    }

    @Test
    public void test3destroy()
    {
        String token = store.getSessions().get(0).getToken();

        store.destroyToken(token);

        assertThat(store.getSessions().isEmpty(), is(true));
    }

    @Test
    public void test10expire() throws NotFoundException
    {
        String token = store.newToken("test@domain.com", "domain.com");

        assertThat(token, is(notNullValue()));
        assertThat(token.length(), is(not(0)));
        assertThat(store.getSessions().size(), is(1));

        Session s = store.getSessions().get(0);

        store.expireSession(s.getId());

        assertThat(store.getSessions().isEmpty(), is(true));
    }

}