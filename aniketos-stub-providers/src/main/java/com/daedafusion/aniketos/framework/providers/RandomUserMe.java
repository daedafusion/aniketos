package com.daedafusion.aniketos.framework.providers;

import com.daedafusion.security.common.Identity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.utils.URIBuilder;
import org.apache.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by mphilpot on 8/20/14.
 */
public class RandomUserMe
{
    private static final Logger log = Logger.getLogger(RandomUserMe.class);

    public static Identity getIdentity(String u, String d)
    {
        String user, domain;

        if(d == null)
        {
            String[] elem = u.split("@");
            user = elem[0];
            domain = elem[1];
        }
        else
        {
            user = u;
            domain = d;
        }

        String seed = Integer.toString(String.format("%s@%s", user, domain).hashCode());

        URI uri = null;
        try
        {
            uri = new URIBuilder("http://api.randomuser.me/0.4.1/").addParameter("seed", seed).build();
        }
        catch (URISyntaxException e)
        {
            log.error("", e);
            throw new RuntimeException(e);
        }

        try
        {
            ObjectMapper mapper = new ObjectMapper();

            Identity id = new Identity();
            id.setIdentifier(seed);

            id.setUsername(user);
            id.setDomain(domain);

            JsonNode node = mapper.readTree(Request.Get(uri).execute().returnContent().asString());

            JsonNode uNode = node.get("results").elements().next().get("user");

            id.setIdentifier(seed);
            id.getAttributes().put(Identity.ATTR_FULLNAME,
                    Collections.singleton(String.format("%s %s", uNode.get("name").get("first").asText(), uNode.get("name").get("last").asText())));
            id.getAttributes().put(Identity.ATTR_FIRSTNAME,
                    Collections.singleton(uNode.get("name").get("first").asText()));
            id.getAttributes().put(Identity.ATTR_LASTNAME,
                    Collections.singleton(uNode.get("name").get("last").asText()));
            id.getAttributes().put(Identity.ATTR_MAIL,
                    Collections.singleton(uNode.get("email").asText()));

            Set<String> capabilities = new HashSet<>();
            capabilities.add("global");
            capabilities.add(String.format("%s", domain));
            capabilities.add(String.format("%s@%s", user, domain));

            if(user.equals("admin"))
            {
                capabilities.add(String.format("#%s", domain));
            }
            if(user.equals("sa"))
            {
                capabilities.add("#global");
            }

            id.getAttributes().put(Identity.ATTR_CAPABILITIES, capabilities);

            byte[] photo = Request.Get(uNode.get("picture").get("thumbnail").asText()).execute().returnContent().asBytes();
            id.getAttributes().put(Identity.ATTR_JPEG_PHOTO,
                    Collections.singleton(Base64.encodeBase64String(photo)));

            return id;
        }
        catch (Exception e)
        {
            log.error("", e);
            throw new RuntimeException(e);
        }
    }
}
