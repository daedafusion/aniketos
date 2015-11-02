package com.daedafusion.aniketos.framework.providers.entities;

import com.daedafusion.configuration.Configuration;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 10/3/14.
 */
@Entity
@Table(name = "identities")
public class HibernateIdentity
{
    private static final Logger log = Logger.getLogger(HibernateIdentity.class);

    @Id
    @GeneratedValue
    @Column(name = "id")
    @Deprecated
    private Long id;

    @Column
    private String username;

    @Column
    private String domain;

    @Column
    private String passwordHash;

    @Column
    private String salt;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(
            name="identity_attribute_join",
            joinColumns=@JoinColumn(name="identity_id"),
            inverseJoinColumns = @JoinColumn(name="identity_attribute_id")
    )
    public List<HibernateIdentityAttribute> attributes;

    public HibernateIdentity()
    {
        attributes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        salt = new BigInteger(130, random).toString(32);
    }

    public boolean comparePassword(String password)
    {
        return passwordHash.equals(generatePasswordHash(password));
    }

    public void setPassword(String password)
    {
        passwordHash = generatePasswordHash(password);
    }

    private String generatePasswordHash(String password)
    {
        String secret = Configuration.getInstance().getString("hmacSecret", "pLbPKQLEXFRnMFWkv9dk");
        String message = String.format("%s%s", salt, password);

        try
        {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            hmac.init(secretKey);

            return Base64.encodeBase64String(hmac.doFinal(message.getBytes()));
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e)
        {
            log.warn("", e);
        }

        return null;
    }


    public Long getId()
    {
        return id;
    }

    public void setId(Long id)
    {
        this.id = id;
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getDomain()
    {
        return domain;
    }

    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    public String getPasswordHash()
    {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash)
    {
        this.passwordHash = passwordHash;
    }

    public String getSalt()
    {
        return salt;
    }

    public void setSalt(String salt)
    {
        this.salt = salt;
    }

    public List<HibernateIdentityAttribute> getAttributes()
    {
        return attributes;
    }

    public void setAttributes(List<HibernateIdentityAttribute> attributes)
    {
        this.attributes = attributes;
    }
}
