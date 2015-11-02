package com.daedafusion.security.providers;

import com.daedafusion.aniketos.AniketosClient;
import com.daedafusion.configuration.Configuration;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.ObjectPool;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.PooledObjectFactory;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/28/14.
 */
public class AniketosClientPool
{
    private static final Logger log = Logger.getLogger(AniketosClientPool.class);

    private static AniketosClientPool ourInstance = new AniketosClientPool();

    private static class AniketosClientObjectFactory extends BasePooledObjectFactory<AniketosClient>
    {

        @Override
        public AniketosClient create() throws Exception
        {
            AniketosClient client = new AniketosClient();

            return client;
        }

        @Override
        public PooledObject<AniketosClient> wrap(AniketosClient aniketosClient)
        {
            return new DefaultPooledObject<>(aniketosClient);
        }
    }

    private class AniketosClientObjectPool extends GenericObjectPool<AniketosClient>
    {

        public AniketosClientObjectPool(PooledObjectFactory<AniketosClient> factory)
        {
            super(factory);
            setLifo(false);
        }
    }

    private ObjectPool<AniketosClient> pool;

    public static AniketosClientPool getInstance()
    {
        return ourInstance;
    }

    private AniketosClientPool()
    {
        pool = new AniketosClientObjectPool(new AniketosClientObjectFactory());
    }

    public ObjectPool<AniketosClient> getPool()
    {
        return pool;
    }
}
