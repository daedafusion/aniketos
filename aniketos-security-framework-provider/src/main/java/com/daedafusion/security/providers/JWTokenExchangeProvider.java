package com.daedafusion.security.providers;

import com.daedafusion.configuration.Configuration;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Principal;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.impl.DefaultAuthenticatedPrincipal;
import com.daedafusion.security.authentication.impl.DefaultToken;
import com.daedafusion.security.authentication.providers.TokenExchangeProvider;
import com.daedafusion.security.common.Identity;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.text.ParseException;
import java.util.*;

/**
 * Created by mphilpot on 10/23/14.
 */
public class JWTokenExchangeProvider extends AbstractProvider implements TokenExchangeProvider
{
    private static final Logger log = Logger.getLogger(JWTokenExchangeProvider.class);

    private KeyPair keyPair;

    private final String sharedSecret;

    public JWTokenExchangeProvider()
    {
        sharedSecret = Configuration.getInstance().getString("jwt.hmacSharedSecret", "sharedSecret");

        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {
                try
                {
                    keyPair = KeyGenUtil.generateKeyPair();
                }
                catch (KeyMaterialException e)
                {
                    log.error("", e);
                }
            }

            @Override
            public void start()
            {

            }

            @Override
            public void stop()
            {

            }

            @Override
            public void teardown()
            {

            }
        });
    }

    @Override
    public boolean canExchange(Token token)
    {
        return isValidToken(token.getTokenString());
    }

    @Override
    public AuthenticatedPrincipal exchange(Token token)
    {
        try
        {
            SignedJWT jwt = SignedJWT.parse(token.getTokenString());

            PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);

            UUID instanceId = UUID.randomUUID();
            Map<String, Set<String>> attributes = new HashMap<>();

            attributes.put(Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME,
                    Collections.singleton(jwt.getJWTClaimsSet().getSubject()));
            attributes.put(Principal.PRINCIPAL_DOMAIN, Collections.singleton(jwt.getJWTClaimsSet().getStringClaim("domain")));
            attributes.put(Principal.PRINCIPAL_NAME, Collections.singleton(jwt.getJWTClaimsSet().getStringClaim("username")));
            attributes.put(Principal.PRINCIPAL_TOKEN, Collections.singleton(token.getTokenString()));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            baos.write(instanceId.toString().getBytes());
            baos.write(Principal.Type.ACCOUNT.toString().getBytes());

            SortedSet<String> sortedKeys = new TreeSet<>(attributes.keySet());

            for(String key: sortedKeys)
            {
                baos.write(key.getBytes());
                for(String s : attributes.get(key)) // TODO need to sort this first
                {
                    baos.write(s.getBytes());
                }
            }

            byte[] sig = crypto.sign(baos.toByteArray());

            String signature = Hex.encodeHexString(sig);

            return new DefaultAuthenticatedPrincipal(
                    instanceId,
                    Principal.Type.ACCOUNT, // TODO How do I know this from a token??
                    attributes,
                    signature
            );
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new RuntimeException(e); // TODO Make this an official exception
        }
    }

    @Override
    public Token exchange(Subject subject)
    {
        // TODO this is sorta sloppy.. should use authority somehow, but that requires agreement on authority string among providers?
        Set<String> tokens = subject.getAttributes(Principal.PRINCIPAL_TOKEN);

        for (String t : tokens)
        {
            if (isValidToken(t))
            {
                return getToken(t);
            }
        }

        throw new RuntimeException("TODO"); // TODO make real exception
    }

    @Override
    public boolean isValidToken(String tokenString)
    {
        try
        {
            SignedJWT jwt = SignedJWT.parse(tokenString);
            JWSVerifier verifier = new MACVerifier(sharedSecret.getBytes());

            if( jwt.verify(verifier) && jwt.getJWTClaimsSet().getExpirationTime().getTime() > System.currentTimeMillis())
            {
                return true;
            }
        }
        catch (ParseException | JOSEException e)
        {
            log.error("", e);
        }

        return false;
    }

    @Override
    public boolean isTokenValid(Token token)
    {
        return isValidToken(token.getTokenString());
    }

    @Override
    public Token getToken(String tokenString)
    {
        return new DefaultToken(getAuthority(), tokenString);
    }

    @Override
    public String getAuthority()
    {
        return JWTokenExchangeProvider.class.getName();
    }

    @Override
    public void destroyToken(Token token)
    {
        throw new UnsupportedOperationException("Not a client method");
    }
}
