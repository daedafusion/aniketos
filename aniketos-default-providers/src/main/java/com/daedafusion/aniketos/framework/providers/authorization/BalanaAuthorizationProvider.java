package com.daedafusion.aniketos.framework.providers.authorization;

import com.daedafusion.aniketos.framework.providers.ServerAuthorizationProvider;
import com.daedafusion.configuration.Configuration;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.sf.LifecycleListener;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import org.w3c.dom.Document;
import org.wso2.balana.Balana;
import org.wso2.balana.PDP;
import org.wso2.balana.PDPConfig;
import org.wso2.balana.ParsingException;
import org.wso2.balana.ctx.*;
import org.wso2.balana.ctx.xacml3.Result;
import org.wso2.balana.finder.AttributeFinderModule;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.PolicyFinderModule;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;


/**
 * Created by mphilpot on 7/19/14.
 */
public class BalanaAuthorizationProvider extends AbstractProvider implements ServerAuthorizationProvider
{
    private static final Logger log = Logger.getLogger(BalanaAuthorizationProvider.class);

    private Balana balana;
    private PDPConfig pdpConfig;

    public BalanaAuthorizationProvider()
    {
        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {
                balana = Balana.getInstance();

                InputStream in = Configuration.getInstance().getResource("policy.xml");

                try
                {
//                    String policyXml = IOUtils.toString(in);

                    PolicyFinder finder = new PolicyFinder();

                    List<Document> policyList = new ArrayList<>();

                    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    factory.setIgnoringComments(true);
                    factory.setNamespaceAware(true);
                    factory.setValidating(false);

                    DocumentBuilder builder = factory.newDocumentBuilder();
                    policyList.add(builder.parse(in));

                    InMemoryPolicyFinderModule mem = new InMemoryPolicyFinderModule(policyList);

                    Set<PolicyFinderModule> policyModules = new HashSet<>();
                    policyModules.add(mem);

                    finder.setModules(policyModules);

                    Balana balana = Balana.getInstance();
                    pdpConfig = balana.getPdpConfig(); // This only has defaults, since we didn't load a PDPConfigFile

                    // TODO need to add a attribute finder that pulls from Identity to get additional attributes
                    //pdpConfig.getAttributeFinder().getModules().add(new IdentityAttributeFinder());

                    pdpConfig = new PDPConfig(pdpConfig.getAttributeFinder(), finder, pdpConfig.getResourceFinder(), true);
                }
                catch (IOException | ParserConfigurationException | SAXException e)
                {
                    log.error("", e);
                }
            }

            @Override
            public void start()
            {

            }

            @Override
            public void stop()
            {

            }

            @Override
            public void teardown()
            {

            }
        });
    }


    @Override
    public String evaluate(String request)
    {
        PDP pdp = new PDP(pdpConfig); // TODO figure out if this is thread safe or not

        ResponseCtx responseCtx;

        try
        {
            AbstractRequestCtx requestCtx = RequestCtxFactory.getFactory().getRequestCtx(request);

            responseCtx = pdp.evaluate(requestCtx);

            return responseCtx.encode();
        }
        catch (ParsingException e)
        {
            log.error("", e);

            Status status = new Status(Collections.singletonList(Status.STATUS_SYNTAX_ERROR), e.getMessage());
            responseCtx = new ResponseCtx(new Result(AbstractResult.DECISION_INDETERMINATE, status));

            return responseCtx.encode();
        }
    }

}
