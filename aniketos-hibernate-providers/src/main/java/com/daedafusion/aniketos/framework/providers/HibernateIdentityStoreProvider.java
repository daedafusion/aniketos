package com.daedafusion.aniketos.framework.providers;

import com.daedafusion.aniketos.framework.providers.daos.DAOFactory;
import com.daedafusion.aniketos.framework.providers.daos.IdentityDAO;
import com.daedafusion.aniketos.framework.providers.entities.HibernateIdentity;
import com.daedafusion.aniketos.framework.providers.entities.HibernateIdentityAttribute;
import com.daedafusion.hibernate.Transaction;
import com.daedafusion.hibernate.TransactionFactory;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.identity.providers.IdentityStoreProvider;
import org.apache.log4j.Logger;

import java.util.*;

/**
 * Created by mphilpot on 10/3/14.
 */
public class HibernateIdentityStoreProvider extends AbstractProvider implements IdentityStoreProvider
{
    private static final Logger log = Logger.getLogger(HibernateIdentityStoreProvider.class);

    @Override
    public Identity getIdentity(Subject subject, String user, String domain)
    {
        IdentityDAO dao = DAOFactory.instance().getIdentityDAO();

        Transaction tm = TransactionFactory.getInstance().get();

        tm.begin();

        HibernateIdentity hid = dao.get(user, domain);

        Identity id = new Identity(user, domain);

        Map<String, Set<String>> attributes = new HashMap<>();

        for(HibernateIdentityAttribute hida : hid.attributes)
        {
            attributes.put(hida.getKey(), hida.getValues());
        }

        id.setAttributes(attributes);

        tm.commit();

        return id;
    }

    @Override
    public List<Identity> getIdentitiesForDomain(Subject subject, String domain)
    {
        IdentityDAO dao = DAOFactory.instance().getIdentityDAO();

        Transaction tm = TransactionFactory.getInstance().get();

        tm.begin();

        List<HibernateIdentity> list = dao.findByDomain(domain);
        List<Identity> result = new ArrayList<>();

        for(HibernateIdentity hid : list)
        {
            Identity id = new Identity(hid.getUsername(), hid.getDomain());
            Map<String, Set<String>> attributes = new HashMap<>();

            for(HibernateIdentityAttribute hida : hid.attributes)
            {
                attributes.put(hida.getKey(), hida.getValues());
            }

            id.setAttributes(attributes);

            result.add(id);
        }

        tm.commit();

        return result;
    }

    @Override
    public void setPassword(Subject subject, String user, String domain, String password)
    {
        IdentityDAO dao = DAOFactory.instance().getIdentityDAO();

        Transaction tm = TransactionFactory.getInstance().get();

        tm.begin();

        HibernateIdentity hid = dao.get(user, domain);

        hid.setPassword(password);

        tm.commit();
    }

    @Override
    public String getAuthority()
    {
        return HibernateIdentityStoreProvider.class.getName();
    }
}
