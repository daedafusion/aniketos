package com.daedafusion.aniketos.entities;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

/**
 * Created by mphilpot on 4/1/15.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JsonTest
{
    private static final Logger log = Logger.getLogger(JsonTest.class);

    private ObjectMapper mapper = new ObjectMapper();

    private void assertAllFieldsSet(Object o)
    {
        try
        {
            for(PropertyDescriptor pd : Introspector.getBeanInfo(o.getClass()).getPropertyDescriptors())
            {
                assertThat(pd.getReadMethod().getName(), pd.getReadMethod().invoke(o), is(notNullValue()));
            }
        }
        catch(Exception e)
        {
            fail(e.getMessage());
        }
    }

    @Test
    public void jsonAuthenticationResponse() throws IOException
    {
        AuthenticationResponse x = new AuthenticationResponse();
        x.setDomain("a");
        x.setMessage("b");
        x.setToken("c");

        assertAllFieldsSet(x);

        String s = mapper.writeValueAsString(x);

        AuthenticationResponse y = mapper.readValue(s, AuthenticationResponse.class);

        assertThat(x, is(y));
        assertThat(x.hashCode(), is(y.hashCode()));
    }

    @Test
    public void jsonTokenValidationResponse() throws IOException
    {
        TokenValidationResponse x = new TokenValidationResponse();
        x.setDomain("a");
        x.setUser("b");
        x.setValid(true);

        assertAllFieldsSet(x);

        String s = mapper.writeValueAsString(x);

        TokenValidationResponse y = mapper.readValue(s, TokenValidationResponse.class);

        assertThat(x, is(y));
        assertThat(x.hashCode(), is(y.hashCode()));
    }
}