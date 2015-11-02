package org.oasis.xacml.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/18/14.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyIdentifier
{
    private static final Logger log = Logger.getLogger(PolicyIdentifier.class);

    @JsonProperty(value = "PolicyIdReference")
    private List<IdReference> policyIdReferences;

    @JsonProperty(value = "PolicySetIdReference")
    private List<IdReference> policySetIdReferences;

    public List<IdReference> getPolicyIdReferences()
    {
        if(policyIdReferences == null)
            policyIdReferences = new ArrayList<>();

        return policyIdReferences;
    }

    public void setPolicyIdReferences(List<IdReference> policyIdReferences)
    {
        this.policyIdReferences = policyIdReferences;
    }

    public List<IdReference> getPolicySetIdReferences()
    {
        if(policySetIdReferences == null)
            policySetIdReferences = new ArrayList<>();

        return policySetIdReferences;
    }

    public void setPolicySetIdReferences(List<IdReference> policySetIdReferences)
    {
        this.policySetIdReferences = policySetIdReferences;
    }
}
