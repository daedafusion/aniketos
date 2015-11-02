package com.daedafusion.aniketos.framework.providers.daos.impl;

import com.daedafusion.aniketos.framework.providers.daos.IdentityDAO;
import com.daedafusion.aniketos.framework.providers.entities.HibernateIdentity;
import com.daedafusion.hibernate.dao.AbstractDAO;
import org.apache.log4j.Logger;
import org.hibernate.Query;

import java.util.List;

/**
 * Created by mphilpot on 10/3/14.
 */
public class IdentityDAOHibernate extends AbstractDAO<HibernateIdentity, Long> implements IdentityDAO
{
    private static final Logger log = Logger.getLogger(IdentityDAOHibernate.class);

    @Override
    public HibernateIdentity get(String username, String domain)
    {
        Query q = getSession().createQuery("from HibernateIdentity i where i.username = :username and i.domain = :domain")
                .setString("username", username).setString("domain", domain);
        return (HibernateIdentity) q.uniqueResult();
    }

    @Override
    public List<HibernateIdentity> findByDomain(String domain)
    {
        Query q = getSession().createQuery("from HibernateIdentity i where i.domain = :domain")
                .setString("domain", domain);

        return q.list();
    }
}
