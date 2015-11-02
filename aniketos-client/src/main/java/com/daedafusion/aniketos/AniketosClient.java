package com.daedafusion.aniketos;

import com.daedafusion.aniketos.exceptions.*;
import com.daedafusion.aniketos.entities.AuthenticationResponse;
import com.daedafusion.aniketos.entities.TokenValidationResponse;
import com.daedafusion.client.AbstractClient;
import com.daedafusion.security.common.Identity;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static java.lang.String.format;

/**
 * Created by mphilpot on 7/24/14.
 */
public class AniketosClient extends AbstractClient
{
    private static final Logger log = Logger.getLogger(AniketosClient.class);

    // Headers
    private static final String ACCEPT = "accept";
    private static final String CONTENT = "content-type";
    private static final String AUTH = "authorization";
    private static final String JSON = "application/json";
    private static final String PASSWORD = "x-identity-password";
    private static final String OLD_PASSWORD = "x-identity-oldpassword";

    public AniketosClient()
    {
        this(null, null);
    }

    public AniketosClient(String url)
    {
        this(url, null);
    }

    public AniketosClient(String url, CloseableHttpClient client)
    {
        super("aniketos", url, client);
    }

    public AuthenticationResponse authenticate(String username, String password)
            throws AccountLockedException, ServiceErrorException, PasswordResetRequiredException, URISyntaxException
    {
        return authenticate(username, null, password);
    }

    public AuthenticationResponse authenticateCert(String b64Cert)
            throws URISyntaxException, AccountLockedException, PasswordResetRequiredException, ServiceErrorException
    {
        URIBuilder builder = new URIBuilder(baseUrl)
                .setPath("/authenticate/certificate");

        URI uri = builder.build();

        HttpPost post = new HttpPost(uri);

        post.addHeader(ACCEPT, JSON);

        post.setEntity(new StringEntity(b64Cert, ContentType.TEXT_PLAIN));

        try
        {
            return client.execute(post, new JsonHandler<AuthenticationResponse>(AuthenticationResponse.class));
        }
        catch(HttpResponseException e)
        {
            if(e.getStatusCode() == 423)
            {
                throw new AccountLockedException(e.getMessage(), e);
            }
            else if(e.getStatusCode() == 419)
            {
                throw new PasswordResetRequiredException(e.getMessage(), e);
            }

            throw new ServiceErrorException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public AuthenticationResponse authenticate(String username, String domain, String password)
            throws URISyntaxException, AccountLockedException, PasswordResetRequiredException, ServiceErrorException
    {
        URIBuilder builder = new URIBuilder(baseUrl).setPath(format("/authenticate/%s", username));

        if(domain != null)
        {
            builder.addParameter("domain", domain);
        }

        URI uri = builder.build();

        HttpPost post = new HttpPost(uri);

        post.addHeader(ACCEPT, JSON);
        post.addHeader(PASSWORD, password);

        try
        {
            return client.execute(post, new JsonHandler<AuthenticationResponse>(AuthenticationResponse.class));
        }
        catch(HttpResponseException e)
        {
            if(e.getStatusCode() == 423)
            {
                throw new AccountLockedException(e.getMessage(), e);
            }
            else if(e.getStatusCode() == 419)
            {
                throw new PasswordResetRequiredException(e.getMessage(), e);
            }

            throw new ServiceErrorException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public AuthenticationResponse authenticateReset(String username, String oldPassword, String newPassword)
            throws AccountLockedException, PasswordQualityException, ServiceErrorException, URISyntaxException
    {
        return authenticateReset(username, null, oldPassword, newPassword);
    }

    public AuthenticationResponse authenticateReset(String username, String domain, String oldPassword, String newPassword)
            throws URISyntaxException, AccountLockedException, PasswordQualityException, ServiceErrorException
    {
        URIBuilder builder = new URIBuilder(baseUrl)
                .setPath(format("/authenticate/reset/%s", username));

        if(domain != null)
        {
            builder.addParameter("domain", domain);
        }

        URI uri = builder.build();

        HttpPost post = new HttpPost(uri);

        post.addHeader(ACCEPT, JSON);
        post.addHeader(PASSWORD, newPassword);
        post.addHeader(OLD_PASSWORD, oldPassword);

        try
        {
            return client.execute(post, new JsonHandler<AuthenticationResponse>(AuthenticationResponse.class));
        }
        catch(HttpResponseException e)
        {
            if(e.getStatusCode() == 423)
            {
                throw new AccountLockedException(e.getMessage(), e);
            }
            else if(e.getStatusCode() == 412)
            {
                throw new PasswordQualityException(e.getMessage(), e);
            }

            throw new ServiceErrorException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public void logout(String token) throws URISyntaxException, ServiceErrorException
    {
        URI uri = new URIBuilder(baseUrl)
                .setPath(format("/logout/%s", token)).build();

        HttpPost post = new HttpPost(uri);

        try
        {
            client.execute(post, new EmptyHandler());
        }
        catch(Exception e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public TokenValidationResponse isTokenValid(String token) throws URISyntaxException, ServiceErrorException
    {
        URI uri = new URIBuilder(baseUrl)
                .setPath(format("/token/%s", token)).build();

        HttpPost post = new HttpPost(uri);

        try
        {
            return client.execute(post, new JsonHandler<TokenValidationResponse>(TokenValidationResponse.class));
        }
        catch(Exception e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public Identity getIdentity(String token) throws URISyntaxException, InvalidTokenException, ServiceErrorException
    {
        URI uri = new URIBuilder(baseUrl)
                .setPath(format("/identity/self/%s", token)).build();

        HttpGet get = new HttpGet(uri);

        try
        {
            return client.execute(get, new JsonHandler<Identity>(Identity.class));
        }
        catch(HttpResponseException e)
        {
            if(e.getStatusCode() == 400)
            {
                throw new InvalidTokenException(e.getMessage(), e);
            }

            throw new ServiceErrorException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public Identity getIdentity(String username, String domain)
            throws URISyntaxException, InvalidTokenException, ServiceErrorException
    {
        URIBuilder builder = new URIBuilder(baseUrl)
                .setPath(format("/identity/%s", username));

        if(domain != null)
        {
            builder.addParameter("domain", domain);
        }

        URI uri = builder.build();

        HttpGet get = new HttpGet(uri);

        get.addHeader(AUTH, getAuthToken());
        get.addHeader(ACCEPT, JSON);

        try
        {
            return client.execute(get, new JsonHandler<Identity>(Identity.class));
        }
        catch(HttpResponseException e)
        {
            if(e.getStatusCode() == 400)
            {
                throw new InvalidTokenException(e.getMessage(), e);
            }

            throw new ServiceErrorException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    public List<Identity> getIdentitiesForDomain(String domain) throws URISyntaxException, InvalidTokenException, ServiceErrorException
    {
        URIBuilder builder = new URIBuilder(baseUrl)
                .setPath(format("/identity/domain/%s", domain));

        URI uri = builder.build();

        HttpGet get = new HttpGet(uri);

        get.addHeader(AUTH, getAuthToken());
        get.addHeader(ACCEPT, JSON);

        try(CloseableHttpResponse response = client.execute(get))
        {
            ObjectMapper mapper = new ObjectMapper();

            return mapper.readValue(EntityUtils.toString(response.getEntity()), new TypeReference<List<Identity>>(){});
        }
        catch(HttpResponseException e)
        {
            if(e.getStatusCode() == 400)
            {
                throw new InvalidTokenException(e.getMessage(), e);
            }

            throw new ServiceErrorException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ServiceErrorException(e.getMessage(), e);
        }
    }

    @Override
    public void close() throws IOException
    {
        client.close();
    }

    public static class EmptyHandler implements ResponseHandler
    {

        @Override
        public Object handleResponse(HttpResponse response) throws ClientProtocolException, IOException
        {
            StatusLine statusLine = response.getStatusLine();
            HttpEntity entity = response.getEntity();

            if(statusLine.getStatusCode() >= 300)
            {
                if(entity != null)
                {
                    throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase() + IOUtils.toString(entity.getContent()));
                }
                else
                {
                    throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
                }
            }

            EntityUtils.consumeQuietly(entity);

            return null;
        }
    }

    private static class JsonHandler<T> implements ResponseHandler<T>
    {
        private Class<T> clazz;

        public JsonHandler(Class<T> clazz)
        {
            this.clazz = clazz;
        }

        @Override
        public T handleResponse(HttpResponse response) throws ClientProtocolException, IOException
        {
            StatusLine statusLine = response.getStatusLine();
            HttpEntity entity = response.getEntity();

            if(statusLine.getStatusCode() >= 300)
            {
                if(entity != null)
                {
                    throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase() + IOUtils.toString(entity.getContent()));
                }
                else
                {
                    throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
                }
            }

            if(entity == null)
            {
                throw new ClientProtocolException("Response contains no content");
            }

            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            return mapper.readValue(entity.getContent(), clazz);
        }
    }
}
