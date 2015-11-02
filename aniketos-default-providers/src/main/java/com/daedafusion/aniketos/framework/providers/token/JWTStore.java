package com.daedafusion.aniketos.framework.providers.token;

import com.daedafusion.configuration.Configuration;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.common.Session;
import com.daedafusion.security.exceptions.NotFoundException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Closeable;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Created by mphilpot on 7/21/14.
 */
public class JWTStore implements Closeable
{

    private static final Logger log = Logger.getLogger(JWTStore.class);

    private static JWTStore ourInstance = new JWTStore();

//    private RSAPublicKey  publicKey;
//    private RSAPrivateKey privateKey;

    private String sharedSecret;

    private Map<Identity, List<String>> userToTokenMap;
    private Map<String, Identity>         tokenToUserMap;

    // Key => token
    private Map<String, Session> sessions;

    private long maxSessionTime;
    private long maxIdleTime;
    private int  maxConcurrentSessions;

    private Timer timer;

    public static JWTStore getInstance()
    {
        return ourInstance;
    }

    private JWTStore()
    {
        userToTokenMap = new ConcurrentHashMap<>();
        tokenToUserMap = new ConcurrentHashMap<>();
        sessions = new ConcurrentHashMap<>();

        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.generateKeyPair();

//            publicKey = (RSAPublicKey) kp.getPublic();
//            privateKey = (RSAPrivateKey) kp.getPrivate();
            sharedSecret = Configuration.getInstance().getString("jwt.hmacSharedSecret", "sharedSecret");

            maxSessionTime = Configuration.getInstance().getLong("session.maxTime", TimeUnit.DAYS.toMillis(1));
            maxIdleTime = Configuration.getInstance().getLong("session.idleTime", TimeUnit.MINUTES.toMillis(30));
            maxConcurrentSessions = Configuration.getInstance().getInteger("session.maxConcurrent", 5);

            timer = new Timer();

            timer.scheduleAtFixedRate(new SessionWatcher(), 0, TimeUnit.SECONDS.toMillis(30));
        }
        catch (NoSuchAlgorithmException e)
        {
            log.error("This should not happen", e);
        }
    }

    @Override
    public void close() throws IOException
    {
        if(timer != null)
        {
            timer.cancel();
        }
    }

    private class SessionWatcher extends TimerTask
    {
        @Override
        public void run()
        {
            for(Map.Entry<String, Session> entry : sessions.entrySet())
            {
                String token = entry.getKey();
                Session session = entry.getValue();

                long now = System.currentTimeMillis();

                if(now > session.getSessionExpiration())
                {
                    destroyToken(token);
                }

                if(now - session.getLastActive() > maxIdleTime)
                {
                    destroyToken(token);
                }
            }
        }
    }

    public boolean isValidToken(String tokenString, boolean pingSession)
    {
        if(tokenToUserMap.containsKey(tokenString))
        {
            Session session = sessions.get(tokenString);

            if(pingSession)
            {
                session.setLastActive(System.currentTimeMillis());
            }

            // Could verify the token cryptographically, but seems unnecessary

            return true;
        }

        return false;
    }

    // TODO Might be able to do better than a big synchronized method
    public synchronized String newToken(String user, String domain)
    {
        Identity id = new Identity(user, domain);
        id.setIdentifier(String.format("%s@%s", user, domain));

        if(!userToTokenMap.containsKey(id))
        {
            userToTokenMap.put(id, new ArrayList<String>(maxConcurrentSessions));
        }

        List<String> list = userToTokenMap.get(id);

        if(list.size() == maxConcurrentSessions)
        {
            String oldToken = list.get(0);
            destroyToken(oldToken);
        }

        DateTime now = new DateTime(DateTimeZone.UTC);

        //JWSSigner signer = new RSASSASigner(privateKey);
        JWSSigner signer = new MACSigner(sharedSecret.getBytes());

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setSubject(id.getDomainQualifiedUsername());
        claimsSet.setIssueTime(now.toDate());
        claimsSet.setNotBeforeTime(now.minusHours(1).toDate());
        claimsSet.setExpirationTime(now.plusMillis((int) maxSessionTime).toDate());
        claimsSet.setCustomClaim("domain", id.getDomain());
        claimsSet.setCustomClaim("username", id.getUsername());

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        try
        {
            signedJWT.sign(signer);
        }
        catch (JOSEException e)
        {
            log.error("", e);
            throw new RuntimeException(e.getMessage());
        }

        String newTokenString = signedJWT.serialize();

        list.add(newTokenString);

        tokenToUserMap.put(newTokenString, id);

        Session session = new Session();
        session.setUser(user);
        session.setDomain(domain);
        session.setToken(newTokenString);
        session.setSessionStart(System.currentTimeMillis());
        session.setSessionExpiration(session.getSessionStart()+maxSessionTime);
        session.setLastActive(session.getSessionStart());

        sessions.put(newTokenString, session);

        return newTokenString;
    }

    public Identity getIdentityForToken(String token)
    {
        return tokenToUserMap.get(token);
    }

    public void destroyToken(String token)
    {
        if(!sessions.containsKey(token))
            return;

        sessions.remove(token);
        Identity id = tokenToUserMap.get(token);
        tokenToUserMap.remove(token);
        List<String> tokens = userToTokenMap.get(id);
        tokens.remove(token);
    }

    public List<Session> getSessions()
    {
        return new ArrayList<>(sessions.values());
    }

    public void expireSession(String sessionId) throws NotFoundException
    {
        String matchingToken = null;

        // TODO make this more efficient
        for(Session session : sessions.values())
        {
            if(session.getId().equals(sessionId))
            {
                matchingToken = session.getToken();
            }
        }

        if(matchingToken != null)
        {
            destroyToken(matchingToken);
        }
        else
        {
            throw new NotFoundException();
        }
    }
}
