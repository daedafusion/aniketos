package com.daedafusion.aniketos.framework.providers.entities;

import org.apache.log4j.Logger;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by mphilpot on 10/3/14.
 */
@Entity
@Table(name = "identity_attributes")
public class HibernateIdentityAttribute
{
    private static final Logger log = Logger.getLogger(HibernateIdentityAttribute.class);

    @Id
    @GeneratedValue
    @Column(name = "id")
    @Deprecated
    private Long id;

    @Column
    private String key;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "identity_attribute_values", joinColumns = @JoinColumn(name = "identity_attribute_id"))
    @Column(name = "values")
    private Set<String> values;

    public HibernateIdentityAttribute()
    {
        values = new HashSet<>();
    }

    public Long getId()
    {
        return id;
    }

    public void setId(Long id)
    {
        this.id = id;
    }

    public String getKey()
    {
        return key;
    }

    public void setKey(String key)
    {
        this.key = key;
    }

    public Set<String> getValues()
    {
        return values;
    }

    public void setValues(Set<String> values)
    {
        this.values = values;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof HibernateIdentityAttribute)) return false;

        HibernateIdentityAttribute that = (HibernateIdentityAttribute) o;

        if (key != null ? !key.equals(that.key) : that.key != null) return false;
        if (values != null ? !values.equals(that.values) : that.values != null) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = key != null ? key.hashCode() : 0;
        result = 31 * result + (values != null ? values.hashCode() : 0);
        return result;
    }
}
