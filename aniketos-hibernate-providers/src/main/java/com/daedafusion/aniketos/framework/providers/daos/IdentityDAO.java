package com.daedafusion.aniketos.framework.providers.daos;

import com.daedafusion.aniketos.framework.providers.entities.HibernateIdentity;
import com.daedafusion.hibernate.dao.GenericDAO;

import java.util.List;

/**
 * Created by mphilpot on 10/3/14.
 */
public interface IdentityDAO extends GenericDAO<HibernateIdentity, Long>
{
    HibernateIdentity get(String username, String domain);

    List<HibernateIdentity> findByDomain(String domain);
}
