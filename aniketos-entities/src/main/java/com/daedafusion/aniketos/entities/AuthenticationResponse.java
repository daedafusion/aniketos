package com.daedafusion.aniketos.entities;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/11/14.
 */
public class AuthenticationResponse
{
    private static final Logger log = Logger.getLogger(AuthenticationResponse.class);

    private String token;
    private String domain;
    private String message;

    public String getToken()
    {
        return token;
    }

    public void setToken(String token)
    {
        this.token = token;
    }

    public String getMessage()
    {
        return message;
    }

    public void setMessage(String message)
    {
        this.message = message;
    }

    public String getDomain()
    {
        return domain;
    }

    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AuthenticationResponse that = (AuthenticationResponse) o;

        if (token != null ? !token.equals(that.token) : that.token != null) return false;
        if (domain != null ? !domain.equals(that.domain) : that.domain != null) return false;
        return !(message != null ? !message.equals(that.message) : that.message != null);

    }

    @Override
    public int hashCode()
    {
        int result = token != null ? token.hashCode() : 0;
        result = 31 * result + (domain != null ? domain.hashCode() : 0);
        result = 31 * result + (message != null ? message.hashCode() : 0);
        return result;
    }
}
