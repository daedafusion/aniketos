package com.daedafusion.aniketos.framework.providers.token;

import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.security.authentication.*;
import com.daedafusion.security.authentication.impl.DefaultAuthenticatedPrincipal;
import com.daedafusion.security.authentication.providers.TokenExchangeProvider;
import com.daedafusion.security.common.Identity;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;

/**
 * Created by mphilpot on 7/19/14.
 */
public class JWTExchangeProvider extends AbstractProvider implements TokenExchangeProvider
{
    private static final Logger log = Logger.getLogger(JWTExchangeProvider.class);

    private String matchedPrincipalAuthority;

    private KeyPair keyPair;

    public JWTExchangeProvider()
    {
        try
        {
            keyPair = KeyGenUtil.generateKeyPair();
        }
        catch( KeyMaterialException e )
        {
            log.error("", e);
        }

        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {
                matchedPrincipalAuthority = getProperty("matchedPrincipalAuthority", null);
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
        return token.getAuthority().equals(getAuthority());

    }

    @Override
    public AuthenticatedPrincipal exchange(Token token)
    {
        String tokenString = token.getTokenString();

        if (!JWTStore.getInstance().isValidToken(tokenString, true))
        {
            throw new RuntimeException();
        }

        Identity stubIdentity = JWTStore.getInstance().getIdentityForToken(tokenString);

        UUID instanceId = UUID.randomUUID();

        Map<String, Set<String>> attributes = new HashMap<>();
        PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);
        String signature = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        String creationTime = Long.toString( System.currentTimeMillis() ) ;
        attributes.put( Principal.PRINCIPAL_CREATION_TIME,
                Collections.singleton(creationTime) );

        //  Use 1.3.6.1.4.1.43975.3.1.1.1 (LDAP Authentication Provider) as the PRINCIPAL_AUTHORITY
        attributes.put( Principal.PRINCIPAL_AUTHORITY,
                Collections.singleton("1.3.6.1.4.1.43975.3.1.1.1"));

        // use domain into which the authentication occurred as the PRINCIPAL_DOMAIN
        attributes.put( Principal.PRINCIPAL_DOMAIN,
                Collections.singleton( stubIdentity.getDomain() ));

        // use the LDAP uid for the user as the PRINCIPAL_NAME
        attributes.put( Principal.PRINCIPAL_NAME,
                Collections.singleton( stubIdentity.getUsername() ) );

        // use username@domain as the PRINCIPAL_DOMAIN_QUALIFIED_NAME
        attributes.put( Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME,
                Collections.singleton( stubIdentity.getIdentifier() ) );

        //Use the LDAP fully qualified DN of the user for the PRINCIPAL_IDENTIFIER
        attributes.put( Principal.PRINCIPAL_IDENTIFIER,
                Collections.singleton(stubIdentity.getIdentifier() ) );

        try
        {
            baos.write(instanceId.toString().getBytes());
            baos.write(Principal.Type.ACCOUNT.toString().getBytes());

            TreeSet<String> sortedKeys = new TreeSet<>(attributes.keySet());

            for(String key : sortedKeys)
            {
                baos.write(key.getBytes());

                // For each in set
                for(String v : attributes.get(key))
                {
                    baos.write(v.getBytes());
                }
            }

            byte[] sig = crypto.sign(baos.toByteArray());

            signature = Hex.encodeHexString(sig);
        }
        catch (IOException | CryptoException e)
        {
            log.error("", e);
        }

        // Create the AuthenticatedPrincipal that represents authenticated identity

        return new DefaultAuthenticatedPrincipal( instanceId,
                Principal.Type.ACCOUNT,
                attributes,
                signature );
    }

    @Override
    public Token exchange(Subject subject)
    {
        String user = null;
        String domain = null;

        if(matchedPrincipalAuthority != null)
        {
            for(AuthenticatedPrincipal ap : subject.getPrincipals())
            {
                if(ap.getAuthority().equals(matchedPrincipalAuthority))
                {
                    user = ap.getName();
                    domain = ap.getDomain();
                }
            }
        }

        if(user == null || domain == null)
        {
            // Just pick first
            log.info("Picking first principal name & domain");
            user = subject.getAttributes(Principal.PRINCIPAL_NAME).iterator().next();
            domain = subject.getAttributes(Principal.PRINCIPAL_DOMAIN).iterator().next();
        }

        String tokenString = JWTStore.getInstance().newToken(user, domain);

        return new JWToken(getAuthority(), tokenString);
    }

    @Override
    public boolean isValidToken(String tokenString)
    {
        return JWTStore.getInstance().isValidToken(tokenString, true);
    }

    @Override
    public boolean isTokenValid(Token token)
    {
        return JWTStore.getInstance().isValidToken(token.getTokenString(), true);
    }

    @Override
    public Token getToken(String tokenString)
    {
        if(JWTStore.getInstance().isValidToken(tokenString, true))
        {
            return new JWToken(getAuthority(), tokenString);
        }

        return null;
    }

    @Override
    public String getAuthority()
    {
        return JWTExchangeProvider.class.getName();
    }

    @Override
    public void destroyToken(Token token)
    {
        JWTStore.getInstance().destroyToken(token.getTokenString());
    }
}
