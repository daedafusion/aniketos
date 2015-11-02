package com.daedafusion.aniketos.framework.providers;

import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Principal;
import com.daedafusion.security.authentication.SharedAuthenticationState;
import com.daedafusion.security.authentication.impl.DefaultAuthenticatedPrincipal;
import com.daedafusion.security.authentication.providers.AuthenticationProvider;
import com.daedafusion.security.common.Callback;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.common.impl.DefaultCallback;
import com.google.common.base.Preconditions;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 8/20/14.
 */
public class StubAuthenticationProvider extends AbstractProvider implements AuthenticationProvider
{
    private static final Logger log = Logger.getLogger(StubAuthenticationProvider.class);

    private Map<UUID, SharedAuthenticationState> sessions;
    private KeyPair keyPair;

    public StubAuthenticationProvider()
    {
        sessions = new ConcurrentHashMap<>();
        try
        {
            keyPair = KeyGenUtil.generateKeyPair();
        }
        catch( KeyMaterialException e )
        {
            log.error("", e);
        }
    }

    @Override
    public UUID initialize(SharedAuthenticationState state)
    {
        Preconditions.checkNotNull(state);

        UUID sessionId = UUID.randomUUID();
        sessions.put( sessionId, state );

        return sessionId;
    }

    @Override
    public boolean login(UUID id, CallbackHandler handler)
    {
        Preconditions.checkNotNull(handler);
        Preconditions.checkNotNull(id);
        Preconditions.checkState(sessions.containsKey(id));

        SharedAuthenticationState state = sessions.get(id);

        List<Callback> callbacks = new ArrayList<>();
        callbacks.add( new DefaultCallback( Callback.DOMAIN ) );
        callbacks.add( new DefaultCallback( Callback.USERNAME ) );
        callbacks.add( new DefaultCallback( Callback.PASSWORD ) );

        handler.handle(callbacks.toArray(new Callback[callbacks.size()]));

        for ( Callback cb : callbacks )
        {
            if (cb.getName().equals(Callback.DOMAIN) && cb.getValue() != null)
            {
                state.addState(Callback.DOMAIN, cb.getValue());
            }
            else if ( cb.getName().equals(Callback.USERNAME) && cb.getValue() != null )
            {
                state.addState(Callback.USERNAME, cb.getValue());
            }
            else if ( cb.getName().equals(Callback.PASSWORD) && cb.getValue() != null )
            {
                state.addState(Callback.PASSWORD, cb.getValue());
            }
        }

        // Stub Implementation so there is one domain that fails
        if(state.getState(Callback.DOMAIN) == null && state.getState(Callback.USERNAME) != null )
        {
            return !((String)state.getState(Callback.USERNAME)).contains("@fail.com");
        }
        else if(state.getState(Callback.DOMAIN) != null)
        {
            return !state.getState(Callback.DOMAIN).equals("fail.com");
        }

        return false;
    }

    @Override
    public AuthenticatedPrincipal commit(UUID id)
    {
        Preconditions.checkNotNull(id);
        Preconditions.checkState(sessions.containsKey(id));

        SharedAuthenticationState state = sessions.get(id);

        UUID instanceId = UUID.randomUUID();

        Map<String, Set<String>> attributes = new HashMap<>();
        PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);
        String signature = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        String creationTime = Long.toString(System.currentTimeMillis()) ;
        attributes.put( Principal.PRINCIPAL_CREATION_TIME,
                Collections.singleton(creationTime) );

        //  Use 1.3.6.1.4.1.43975.3.1.1.1 (LDAP Authentication Provider) as the PRINCIPAL_AUTHORITY
        attributes.put( Principal.PRINCIPAL_AUTHORITY,
                Collections.singleton("1.3.6.1.4.1.43975.3.1.1.1"));

        String domain = (String) state.getState(Callback.DOMAIN);
        String username = (String) state.getState(Callback.USERNAME);

        if(domain == null)
        {
            int index = ((String)state.getState(Callback.USERNAME)).indexOf("@");
            domain = ((String)state.getState(Callback.USERNAME)).substring(index+1);
            username = ((String)state.getState(Callback.USERNAME)).substring(0, index);
        }

        // use domain into which the authentication occurred as the PRINCIPAL_DOMAIN
        attributes.put( Principal.PRINCIPAL_DOMAIN,
                Collections.singleton(domain) );

        // use the LDAP uid for the user as the PRINCIPAL_NAME
        attributes.put( Principal.PRINCIPAL_NAME,
                Collections.singleton(username) );

        String fqn = (String) state.getState(Callback.USERNAME);

        if(state.getState(Callback.DOMAIN) != null)
        {
            fqn = String.format("%s@%s", state.getState(Callback.USERNAME), state.getState(Callback.DOMAIN));
        }

        // use username@domain as the PRINCIPAL_DOMAIN_QUALIFIED_NAME
        attributes.put( Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME,
                Collections.singleton(fqn) );

        //Use the LDAP fully qualified DN of the user for the PRINCIPAL_IDENTIFIER
        attributes.put( Principal.PRINCIPAL_IDENTIFIER,
                Collections.singleton(fqn) );

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
        AuthenticatedPrincipal ap = new DefaultAuthenticatedPrincipal( instanceId,
                Principal.Type.ACCOUNT,
                attributes,
                signature );

        sessions.remove(id);

        return ap;
    }

    @Override
    public void logoff(AuthenticatedPrincipal principal)
    {
        return;
    }

    @Override
    public void abort(UUID id)
    {
        Preconditions.checkNotNull(id);
        Preconditions.checkState(sessions.containsKey(id));

        sessions.remove(id);
    }

    @Override
    public boolean verify(AuthenticatedPrincipal principal)
    {
        return false;
    }

    @Override
    public String getAuthority()
    {
        return StubAuthenticationProvider.class.getName();
    }
}
