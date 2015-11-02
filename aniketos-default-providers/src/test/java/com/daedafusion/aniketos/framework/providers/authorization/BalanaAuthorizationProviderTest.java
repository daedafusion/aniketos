package com.daedafusion.aniketos.framework.providers.authorization;

import com.daedafusion.sf.LifecycleListener;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.junit.Ignore;
import org.junit.Test;
import org.oasis.xacml.jaxb.Response;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.IOException;
import java.io.StringReader;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by mphilpot on 8/12/14.
 */
public class BalanaAuthorizationProviderTest
{
    private static final Logger log = Logger.getLogger(BalanaAuthorizationProviderTest.class);

    @Test
    public void main() throws JAXBException, IOException
    {
        BalanaAuthorizationProvider bap = new BalanaAuthorizationProvider();

        for(LifecycleListener ll : bap.getListeners())
        {
            ll.init();
        }

        String req = IOUtils.toString(
                BalanaAuthorizationProviderTest.class.getClassLoader().getResourceAsStream("requests/request_0001_01.xml"));

        Unmarshaller responseUnmarshaller = JAXBContext.newInstance(Response.class).createUnmarshaller();

        Response truth = (Response) responseUnmarshaller.unmarshal(
                BalanaAuthorizationProviderTest.class.getClassLoader().getResourceAsStream("responses/response_0001_01.xml"));

        String resp = bap.evaluate(req);

        Response value = (Response) responseUnmarshaller.unmarshal(new StringReader(resp));

        assertThat(value.equals(truth), is(true));
    }
}
