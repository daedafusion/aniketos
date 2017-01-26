package com.daedafusion.security.providers;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.Principal;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.ResourceActionContext;
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.decision.Decision;
import org.apache.log4j.Logger;
import org.oasis.xacml.XacmlConstants;
import org.oasis.xacml.jaxb.Attribute;
import org.oasis.xacml.jaxb.AttributeValueType;
import org.oasis.xacml.jaxb.Attributes;
import org.oasis.xacml.jaxb.Request;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * Created by mphilpot on 7/29/14.
 */
public class AniketosRemoteAuthorizationProvider extends AbstractProvider implements AuthorizationProvider
{
    private static final Logger log = Logger.getLogger(AniketosRemoteAuthorizationProvider.class);

    @Override
    public Decision getAccessDecision(Subject subject, URI resource, String action, Context context)
    {
        Request request = new Request();

        return null;
    }

    @Override
    public Decision getAccessDecision(Subject subject, HttpServletRequest request, Context context)
    {
        return null;
    }

    @Override
    public Decision[] getAccessDecisionSet(Subject subject, List<ResourceActionContext> resourceActionContext)
    {
        return new Decision[0];
    }

    private Attributes getSubjectAttributes(Subject subject)
    {
        Attributes attrs = new Attributes();
        attrs.setCategory(XacmlConstants.Categories.ACCESS_SUBJECT);
        attrs.getAttributes().add(
                getAttribute(XacmlConstants.Attributes.SUBJECT_ID,
                        XacmlConstants.DataTypes.STRING,
                        subject.getAttributes(Principal.PRINCIPAL_NAME)));

        return attrs;
    }

    private Attribute getAttribute(String attributeId, String dataType, Set<String> values)
    {
        Attribute attr = new Attribute();
        attr.setAttributeId(attributeId);

        AttributeValueType avt = new AttributeValueType();
        avt.setDataType(dataType);

        for(String v : values)
        {
            avt.getContent().add(v);
        }

        attr.getAttributeValues().add(avt);

        return attr;
    }
}
