package com.daedafusion.security.providers;

import com.daedafusion.aniketos.AniketosClient;
import com.daedafusion.aniketos.entities.AuthenticationResponse;
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
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Callback;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.common.impl.DefaultCallback;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 10/2/14.
 */
public class AniketosCertAuthenticationProvider extends AbstractProvider implements AuthenticationProvider
{
    private static final Logger log = Logger.getLogger(AniketosCertAuthenticationProvider.class);

    private final Map<UUID, SharedAuthenticationState> sessions;
    private       KeyPair                              keyPair;

    public AniketosCertAuthenticationProvider()
    {
        sessions = new ConcurrentHashMap<>();

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
    public UUID initialize(SharedAuthenticationState state)
    {
        UUID sessionId = UUID.randomUUID();
        sessions.put(sessionId, state);

        return sessionId;
    }

    @Override
    public boolean login(UUID id, CallbackHandler handler) throws AccountLockedException, PasswordResetRequiredException, PasswordQualityException
    {
        SharedAuthenticationState state = sessions.get(id);

        List<Callback> callbacks = new ArrayList<>();

        callbacks.add(new DefaultCallback(Callback.X509));

        handler.handle(callbacks.toArray(new Callback[1]));

        for (Callback cb : callbacks)
        {
            if (cb.getName().equals(Callback.X509) && cb.getValue() != null)
            {
                state.addState(Callback.X509, cb.getValue());
            }
        }

        if (!state.hasState(Callback.X509))
        {
            return false;
        }

        AniketosClient client = null;
        try
        {
            client = AniketosClientPool.getInstance().getPool().borrowObject();

            AuthenticationResponse response = client.authenticateCert((String) state.getState(Callback.X509));

            if (response.getToken() != null)
            {
                state.addState("token", response.getToken());

                return true;
            }
        }
        catch (Exception e)
        {
            log.error("", e);
        }
        finally
        {
            if(client != null)
            {
                try
                {
                    AniketosClientPool.getInstance().getPool().returnObject(client);
                }
                catch (Exception e)
                {
                    log.error("", e);
                }
            }
        }

        return false;
    }

    @Override
    public AuthenticatedPrincipal commit(UUID id)
    {
        SharedAuthenticationState state = sessions.get(id);

        Map<String, Set<String>> attributes = new HashMap<>();

        // TODO copy identity into attributes
        attributes.put(Principal.PRINCIPAL_TOKEN, Collections.singleton((String) state.getState("token")));

        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);

            baos.write(id.toString().getBytes());
            baos.write(Principal.Type.ACCOUNT.toString().getBytes());

            SortedSet<String> sortedKeys = new TreeSet<>(attributes.keySet());

            for (String key : sortedKeys)
            {
                baos.write(key.getBytes());
                for (String s : attributes.get(key)) // TODO need to sort this first
                {
                    baos.write(s.getBytes());
                }
            }

            byte[] sig = crypto.sign(baos.toByteArray());

            String signature = Hex.encodeHexString(sig);

            AuthenticatedPrincipal principal = new DefaultAuthenticatedPrincipal(
                    id,
                    Principal.Type.MACHINE, // TODO I don't know this for certain... need to inspect attributes
                    attributes,
                    signature
            );

            sessions.remove(id);

            return principal;
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new RuntimeException(e); // TODO Make this an official exception
        }
    }

    @Override
    public void logoff(AuthenticatedPrincipal principal)
    {
        Set<String> tokens = principal.getAttributes(Principal.PRINCIPAL_TOKEN);

        if(tokens.isEmpty() || tokens.size() > 1)
        {
            log.warn(String.format("Invalid token state :: %s", tokens));
            return;
        }

        String token = tokens.iterator().next();

        AniketosClient client = null;
        try
        {
            client = AniketosClientPool.getInstance().getPool().borrowObject();

            client.logout(token);
        }
        catch (Exception e)
        {
            log.error("", e);
        }
        finally
        {
            if(client != null)
            {
                try
                {
                    AniketosClientPool.getInstance().getPool().returnObject(client);
                }
                catch (Exception e)
                {
                    log.error("", e);
                }
            }
        }
    }

    @Override
    public void abort(UUID id)
    {
        sessions.remove(id);

        // TODO do I need to see if there is a token in the state and logout?
    }

    @Override
    public boolean verify(AuthenticatedPrincipal principal)
    {
        try
        {
            byte[] sig = Hex.decodeHex(principal.getSignature().toCharArray());

            PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            baos.write(principal.getInstanceId().toString().getBytes());
            baos.write(principal.getType().toString().getBytes());

            TreeSet<String> sortedKeys = new TreeSet<>(principal.getAttributeNames());

            for(String key : sortedKeys)
            {
                baos.write(key.getBytes());
                // TODO
                // for each in set
                //baos.write(principal.getAttributes(key).getBytes());
            }

            return crypto.verify(sig, baos.toByteArray());
        }
        catch (DecoderException | CryptoException | IOException e)
        {
            log.error("", e);
        }

        return false;
    }

    @Override
    public String getAuthority()
    {
        return AniketosCertAuthenticationProvider.class.getName();
    }
}
