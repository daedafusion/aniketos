package com.daedafusion.aniketos.framework.providers.audit;

import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.audit.AuditEvent;
import com.daedafusion.security.audit.providers.AuditProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Created by mphilpot on 8/12/14.
 */
public class Log4jInstanceKeyAuditLogProvider extends AbstractProvider implements AuditProvider
{
    private static final Logger log = Logger.getLogger(Log4jInstanceKeyAuditLogProvider.class);

    private RSAPublicKey  publicKey;
    private RSAPrivateKey privateKey;

    public Log4jInstanceKeyAuditLogProvider()
    {
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.generateKeyPair();

            publicKey = (RSAPublicKey) kp.getPublic();
            privateKey = (RSAPrivateKey) kp.getPrivate();

            log.warn("Audit Service Restart");
            log.warn(String.format("Instance Keys %s :: %s",
                    Base64.encodeBase64String(publicKey.getEncoded()),
                    Base64.encodeBase64String(privateKey.getEncoded())));
        }
        catch (NoSuchAlgorithmException e)
        {
            log.error("This shouldn't happen", e);
        }
    }

    @Override
    public void reportEvent(AuditEvent event)
    {
        ObjectMapper mapper = new ObjectMapper();

        try
        {
            String message = mapper.writeValueAsString(event);

            TimeZone tz = TimeZone.getDefault();
            DateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            isoFormat.setTimeZone(tz);
            String iso = isoFormat.format(new Date());

            PublicCrypto pki = CryptoFactory.getInstance().getPublicCrypto(new KeyPair(publicKey, privateKey));

            byte[] sig = pki.sign(message.getBytes());

            log.info(String.format("%s %s %s",
                    iso,
                    Hex.encodeHexString(sig),
                    message));
        }
        catch (JsonProcessingException | CryptoException e)
        {
            log.error("", e);
        }
    }
}
