package com.daedafusion.aniketos;

import com.daedafusion.service.bootstrap.*;
import com.daedafusion.configuration.Configuration;
import com.daedafusion.discovery.DiscoveryRegistrationListener;
import com.daedafusion.service.JettyServerBuilder;
import com.daedafusion.service.OptionsUtil;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.bindings.AuthorizationTokenFilter;
import org.apache.commons.cli.*;
import org.apache.log4j.Logger;
import org.eclipse.jetty.server.Server;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Created by mphilpot on 7/25/14.
 */
public class Main
{
    private static final Logger log = Logger.getLogger(Main.class);

    public static void main(String[] args) throws Exception
    {
        // Process Command Line Options
        Options options = OptionsUtil.getStandardServerOptions();
        CommandLineParser parser = new PosixParser();

        CommandLine cmd = parser.parse(options, args);

        if(cmd.hasOption("h"))
        {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(String.format("java -jar %s [options] [args]", "server.jar"), options);
            return;
        }

        List<Bootstrap> bootstraps = new ArrayList<>();

        BootstrapConfig bootstrapConfig = new BootstrapConfig();

        if(cmd.hasOption("b"))
        {
            String bootstrapProperties = cmd.getOptionValue("b");

            bootstrapConfig.setBootstrapFile(bootstrapProperties);
        }

        bootstrapConfig.boot();

        bootstraps.add(bootstrapConfig);

        bootstraps.add(new BootstrapCrypto().boot());
        bootstraps.add(new BootstrapDefaultLogging().boot());
        bootstraps.add(new BootstrapServiceFramework().boot());

        // Setup Server
        JettyServerBuilder builder = new JettyServerBuilder();

        builder.newServletContext().addJerseyApplication(Application.class);

        //builder.addFilter(new AuthorizationTokenFilter());

        ServiceFramework framework = ServiceFrameworkFactory.getInstance().getFramework();

        Map<String, Object> objects = framework.getServiceRegistry().getExternalResources();

        for(Object obj : objects.values())
        {
            if(obj instanceof Filter)
            {
                builder.addFilter((Filter) obj);
            }
        }

        if(cmd.hasOption("s"))
        {
            builder.addSslConnector(Configuration.getInstance().getInteger("servicePort", 30001), cmd.hasOption("m"));
        }
        else
        {
            builder.addDefaultConnector(Configuration.getInstance().getInteger("servicePort", 30001));
        }

        DiscoveryRegistrationListener discoveryListener = null;

        if(cmd.hasOption("H"))
        {
            discoveryListener = new DiscoveryRegistrationListener(
                    Configuration.getInstance().getString("serviceName", "aniketos"),
                    cmd.getOptionValue("H"),
                    Configuration.getInstance().getInteger("servicePort", 30001),
                    cmd.hasOption("s")
            );
        }
        else
        {
            discoveryListener = new DiscoveryRegistrationListener(
                    Configuration.getInstance().getString("serviceName", "aniketos"),
                    Configuration.getInstance().getInteger("servicePort", 30001),
                    cmd.hasOption("s")
            );
        }

        builder.addListener(discoveryListener);

        Server server = builder.build();

        try
        {
            server.start();
            server.join();
        }
        catch(Exception e)
        {
            log.warn("", e);
            server.stop();
        }
        finally
        {
            Collections.reverse(bootstraps);

            for(Bootstrap b : bootstraps)
            {
                b.teardown();
            }
        }
    }
}
