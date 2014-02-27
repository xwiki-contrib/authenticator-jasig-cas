/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.authentication.cas;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.authentication.cas.internal.UserUtils;
import org.xwiki.contrib.authentication.cas.internal.XWikiCASConfig;
import org.xwiki.model.reference.DocumentReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Authentication based on Jasig CAS server. It creates XWiki users if they have never logged in before and synchronizes
 * membership to XWiki groups based on membership to CAS group field mapping.
 * <p>
 * Some parameters can be used to customized its behavior in xwiki.cfg:
 * <ul>
 * <li>xwiki.authentication.cas.server: CAS server url (i.e. https://localhost:8443/cas)</li>
 * <li>xwiki.authentication.cas.protocol: used protocol CAS20 or SAML11</li>
 * <li>xwiki.authentication.cas.access_denied_page: user not authorized page (i.e.
 * /bin/view/XWiki/XWikiCASAccessDenied). If not set a HTTP status 401 is returned.</li>
 * <li>xwiki.authentication.cas.create_user: 0 or 1 if create XWiki user after log in</li>
 * <li>xwiki.authentication.cas.update_user: 0 or 1 if update user attributes after every log in</li>
 * <li>xwiki.authentication.cas.fields_mapping: mapping between XWiki user profile values and CAS attributes. Example
 * (xwiki-attribute=cas-attribute,...): <code>last_name=lastName,first_name=firstName,email=email</code></li>
 * <li>xwiki.authentication.cas.group_field: CAS attribute name which contains group membership</li>
 * <li>xwiki.authentication.cas.group_mapping: Maps XWiki groups to CAS groups, separator is "|".
 * XWiki.XWikiAdminGroup=cn=AdminRole,ou=groups,o=domain,c=com| XWiki.CASUsers=ou=groups,o=domain,c=com</li>
 * </ul>
 * 
 * @version $Id$
 */
public class XWikiCASAuthenticator extends XWikiAuthServiceImpl
{

    /** LogFactory <code>LOGGER</code>. */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiCASAuthenticator.class);

    /**
     * The XWiki space where users are stored.
     */
    private static final String XWIKI_USER_SPACE = "XWiki";

    /**
     * Request wrapper auth method
     */
    private static final String AUTH_METHOD = "CAS";

    /**
     * {@inheritDoc}
     * 
     * @see com.xpn.xwiki.user.impl.xwiki.AppServerTrustedAuthServiceImpl#checkAuth(com.xpn.xwiki.XWikiContext)
     */
    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CAS authentication started");
        }

        SecurityRequestWrapper wrappedRequest =
            new SecurityRequestWrapper(context.getRequest().getHttpServletRequest(), null, null, AUTH_METHOD);

        if ("login".equals(context.getAction())) {
            String ticket = context.getRequest().getParameter("ticket");

            if (ticket == null) {
                // redirect to the CAS login page

                try {
                    XWikiCASConfig config = XWikiCASConfig.getInstance();

                    String casServer = config.getCASParam("cas_server", "", context);

                    String serviceUrl = URLEncoder.encode(createServiceUrl(context), "UTF-8");
                    context.getResponse().sendRedirect(
                        context.getResponse().encodeRedirectURL(casServer + "/login?service=" + serviceUrl));
                } catch (IOException e) {
                    throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                        "Can't redirect to the CAS login page", e);
                }
                return null;

            } else {
                // authenticate using CAS ticket

                Principal principal = authenticate(ticket, context);

                if (principal != null) {
                    // login successful
                    if (LOGGER.isInfoEnabled()) {
                        LOGGER.info("User " + principal.getName() + " has been logged-in");
                    }

                    // invalidate old session if the user was already
                    // authenticated,
                    // and they logged in as a different user
                    if (wrappedRequest.getUserPrincipal() != null
                        && !principal.getName().equals(wrappedRequest.getRemoteUser())) {
                        wrappedRequest.getSession().invalidate();
                    }
                } else {
                    XWikiCASConfig config = XWikiCASConfig.getInstance();
                    String failedPage = config.getCASParam("cas_access_denied_page", null, context);
                    try {
                        if (failedPage != null) {
                            context.getResponse().sendRedirect(
                                context.getResponse().encodeRedirectURL(
                                    context.getRequest().getContextPath() + failedPage));
                        } else {
                            context.getResponse().sendError(HttpServletResponse.SC_UNAUTHORIZED);
                        }
                    } catch (IOException e) {
                        throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                            XWikiException.ERROR_XWIKI_USER_INIT, "Can't authenticate user", e);

                    }
                }
                wrappedRequest.setUserPrincipal(principal);
            }

        } else if ("logout".equals(context.getAction()) && wrappedRequest.getUserPrincipal() != null) {
            // TODO redirect to the CAS logout page

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("User " + wrappedRequest.getUserPrincipal().getName() + " has been logged-out");
            }
            wrappedRequest.setUserPrincipal(null);

            // XWikiCASConfig config = XWikiCASConfig.getInstance();
            //
            // String casServer = config.getCASParam("cas_server", "", context);
            //
            // try {
            // context.getResponse().sendRedirect(context.getResponse().encodeRedirectURL(casServer
            // + "/logout"));
            // } catch (IOException e) {
            // throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
            // XWikiException.ERROR_XWIKI_USER_INIT,
            // "Can't redirect to the CAS logout page", e);
            // }
            return null;

        }

        if (wrappedRequest.getUserPrincipal() == null) {
            return null;
        }
        return new XWikiUser(wrappedRequest.getUserPrincipal().getName());
    }

    /**
     * Validate CAS ticket. If success return a principal
     * 
     * @param ticket CAS ticket to validate
     * @param context
     * @return principal of the authenticated user
     * @throws XWikiException
     */
    public Principal authenticate(String ticket, XWikiContext context) throws XWikiException
    {
        Principal principal = null;

        XWikiCASConfig config = XWikiCASConfig.getInstance();

        String casServer = config.getCASParam("cas_server", "", context);

        try {
            // create CAS validator
            TicketValidator validator = null;
            if (config.isSAML11Protocol(context)) {
                validator = new Saml11TicketValidator(casServer);
            } else {
                validator = new Cas20ServiceTicketValidator(casServer);
            }

            // service url creation
            String serviceUrl = createServiceUrl(context);

            // CAS validation
            Assertion assertion = validator.validate(ticket, serviceUrl);

            // get valid wiki username
            String validXWikiUserName = UserUtils.getValidXWikiUserName(assertion.getPrincipal().getName());

            String database = context.getDatabase();
            try {
                // Switch to main wiki to force users to be global users
                context.setDatabase(context.getMainXWiki());

                // user profile
                XWikiDocument userProfile =
                    context.getWiki().getDocument(
                        new DocumentReference(context.getDatabase(), XWIKI_USER_SPACE, validXWikiUserName), context);

                boolean isNewUser = userProfile.isNew();

                // create XWiki principal
                principal = new SimplePrincipal(context.getDatabase() + ":" + userProfile.getFullName());

                if (!config.getCASParam("cas_create_user", "0", context).equals("1")) {
                    // user creation is disabled
                    if (isNewUser) {
                        return null;
                    }

                    return principal;
                }
                
                // update or create user
                UserUtils.syncUser(userProfile, assertion.getPrincipal().getAttributes(), context);

                String casGroupField = config.getCASParam("cas_group_field", null, context);

                // synchronize user XWiki membership with it's CAS membership.
                if (casGroupField != null && assertion.getPrincipal().getAttributes() != null) {
                    try {
                        // get user CAS group field values
                        List<String> casGroups = null;
                        Object v = assertion.getPrincipal().getAttributes().get(casGroupField);
                        if (v instanceof String) {
                            casGroups = new ArrayList<String>();
                            casGroups.add((String) v);
                        } else if (v instanceof List) {
                            casGroups = (List<String>) v;
                        } else {
                            casGroups = new ArrayList<String>();
                        }

                        // synchronize memberships
                        UserUtils.syncGroupsMembership(userProfile.getFullName(), casGroups, isNewUser, context);
                    } catch (XWikiException e) {
                        LOGGER.error("Failed to synchronise user's groups membership", e);
                    }
                } else {
                    if (LOGGER.isDebugEnabled())
                        LOGGER.debug("No cas_group_field defined. Bypass user XWiki membership synchronization.");
                }
            } finally {
                context.setDatabase(database);
            }

        } catch (TicketValidationException e) {
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                "Can't validate CAS ticket.", e);
        }

        return principal;
    }

    /**
     * Create a CAS service url
     * 
     * @param request
     * @return
     */
    private String createServiceUrl(XWikiContext context)
    {
        XWikiRequest request = context.getRequest();
        StringBuilder sb = new StringBuilder();
        String query = request.getQueryString();
        if (query != null) {
            String[] params = query.split("&");
            for (String p : params) {
                if (!p.startsWith("ticket")) {
                    sb.append("&" + p);
                }
            }
            if (sb.length() > 0)
                sb.replace(0, 1, "?");
        }
        String wikiHome = context.getWiki().Param("xwiki.home");
        if (wikiHome != null) {
            sb.insert(0, request.getRequestURI());
            sb.deleteCharAt(0);
            sb.insert(0, wikiHome);
        } else {
            sb.insert(0, request.getRequestURL());
        }
        return sb.toString();
    }

}
