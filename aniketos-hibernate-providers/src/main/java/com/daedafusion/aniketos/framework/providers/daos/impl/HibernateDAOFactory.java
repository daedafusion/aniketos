package com.daedafusion.aniketos.framework.providers.daos.impl;

import com.daedafusion.aniketos.framework.providers.daos.DAOFactory;
import com.daedafusion.aniketos.framework.providers.daos.IdentityDAO;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 10/3/14.
 */
public class HibernateDAOFactory extends DAOFactory
{
    private static final Logger log = Logger.getLogger(HibernateDAOFactory.class);

    @Override
    public IdentityDAO getIdentityDAO()
    {
        return (IdentityDAO) instantiateDAO(IdentityDAOHibernate.class);
    }
}
