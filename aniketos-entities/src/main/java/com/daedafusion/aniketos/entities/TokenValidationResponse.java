package com.daedafusion.aniketos.entities;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/11/14.
 */
public class TokenValidationResponse
{
    private static final Logger log = Logger.getLogger(TokenValidationResponse.class);

    private Boolean valid;
    private String user;
    private String domain;

    public Boolean getValid()
    {
        return valid;
    }

    public void setValid(Boolean valid)
    {
        this.valid = valid;
    }

    public String getUser()
    {
        return user;
    }

    public void setUser(String user)
    {
        this.user = user;
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

        TokenValidationResponse that = (TokenValidationResponse) o;

        if (valid != null ? !valid.equals(that.valid) : that.valid != null) return false;
        if (user != null ? !user.equals(that.user) : that.user != null) return false;
        return !(domain != null ? !domain.equals(that.domain) : that.domain != null);

    }

    @Override
    public int hashCode()
    {
        int result = valid != null ? valid.hashCode() : 0;
        result = 31 * result + (user != null ? user.hashCode() : 0);
        result = 31 * result + (domain != null ? domain.hashCode() : 0);
        return result;
    }
}
