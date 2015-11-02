package com.daedafusion.aniketos.framework.providers.authentication;

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
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 8/27/14.
 */
public class KeyStoreX509AuthProvider extends AbstractProvider implements AuthenticationProvider
{
    private static final Logger log = Logger.getLogger(KeyStoreX509AuthProvider.class);

    private Map<UUID, SharedAuthenticationState> sessions;
    private KeyPair                              keyPair;

    public KeyStoreX509AuthProvider()
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
        callbacks.add( new DefaultCallback( Callback.X509 ) );

        handler.handle(callbacks.toArray(new Callback[callbacks.size()]));

        for ( Callback cb : callbacks )
        {
            if (cb.getName().equals(Callback.X509) )
            {
                if(cb.getValue() != null)
                {
                    state.addState(Callback.X509, cb.getValue());
                }
            }
        }

        if(state.getState(Callback.X509) != null)
        {
            String x509String = (String) state.getState(Callback.X509);

            try
            {
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(
                        new ByteArrayInputStream(Base64.getDecoder().decode(x509String)));

                String rdn = certificate.getSubjectDN().getName();
                X500Name x500name = new X500Name(rdn);
                RDN cn = x500name.getRDNs(BCStyle.CN)[0];

                String alias = IETFUtils.valueToString(cn.getFirst().getValue());
                String issuer = certificate.getIssuerDN().getName();

                if(!CryptoFactory.getInstance().getKeyStore().containsAlias(alias))
                {
                    log.error(String.format("X509 Cert (alias=%s) not found", alias));
                    return false;
                }

                if(((X509Certificate)CryptoFactory.getInstance().getKeyStore().getCertificate(alias)).getSerialNumber()
                        .equals(certificate.getSerialNumber()))
                {
                    state.addState("certificate", certificate);
                    state.addState(Principal.PRINCIPAL_NAME, alias);
                    state.addState(Principal.PRINCIPAL_DOMAIN, issuer);
                    state.addState(Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME, String.format("%s@%s", alias, issuer));
                    return true;
                }
            }
            catch (CertificateException | KeyMaterialException | KeyStoreException e)
            {
                log.error("", e);
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
        attributes.put(Principal.PRINCIPAL_NAME, Collections.singleton((String)state.getState(Principal.PRINCIPAL_NAME)));
        attributes.put(Principal.PRINCIPAL_DOMAIN, Collections.singleton((String)state.getState(Principal.PRINCIPAL_DOMAIN)));
        attributes.put(Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME, Collections.singleton((String)state.getState(Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME)));

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

    }

    @Override
    public void abort(UUID id)
    {

    }

    @Override
    public boolean verify(AuthenticatedPrincipal principal)
    {
        return false;
    }

    @Override
    public String getAuthority()
    {
        return KeyStoreX509AuthProvider.class.getName();
    }
}
