package com.daedafusion.aniketos.framework.providers.authorization;

import org.apache.log4j.Logger;

import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.wso2.balana.Balana;
import org.wso2.balana.PDP;
import org.wso2.balana.PDPConfig;
import org.wso2.balana.ParsingException;
import org.wso2.balana.ctx.AbstractRequestCtx;
import org.wso2.balana.ctx.RequestCtxFactory;
import org.wso2.balana.ctx.ResponseCtx;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.PolicyFinderModule;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * Created by mphilpot on 7/28/14.
 */
public class BalanaExplorationTest
{
    private static final Logger log = Logger.getLogger(BalanaExplorationTest.class);

    @Test
    @Ignore
    public void main() throws ParsingException
    {
        // Setup an in-memory version of balana
        PolicyFinder finder = new PolicyFinder();

        List<Document> policyList = new ArrayList<>();

        // TODO load the policy documents from Configuration (or classload in this case)

        InMemoryPolicyFinderModule mem = new InMemoryPolicyFinderModule(policyList);

        Set<PolicyFinderModule> policyModules = new HashSet<>();
        policyModules.add(mem);

        finder.setModules(policyModules);

        Balana balana = Balana.getInstance();
        PDPConfig pdpConfig = balana.getPdpConfig(); // This only has defaults, since we didn't load a PDPConfigFile
        pdpConfig = new PDPConfig(pdpConfig.getAttributeFinder(), finder, pdpConfig.getResourceFinder(), true);

        PDP pdp = new PDP(pdpConfig);

        String requestXml = ""; // TODO load

        AbstractRequestCtx requestCtx = RequestCtxFactory.getFactory().getRequestCtx(requestXml);

        ResponseCtx responseCtx = pdp.evaluate(requestCtx);
    }
}
