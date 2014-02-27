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
package org.xwiki.contrib.authentication.cas.internal;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.rendering.syntax.Syntax;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;

public class UserUtils
{

    private static final Logger LOGGER = LoggerFactory.getLogger(UserUtils.class);

    /**
     * Separator between space name and document name in document full name.
     */
    private static final String XWIKI_SPACE_NAME_SEP = ".";

    /**
     * The name of the XWiki group member field.
     */
    private static final String XWIKI_GROUP_MEMBERFIELD = "member";

    /**
     * Update or create XWiki user base on CAS.
     * 
     * @param userProfile the profile of the user.
     * @param casAttributes the attributes from CAS.
     * @param context the XWiki context.
     * @throws XWikiException error when updating or creating XWiki user.
     */
    public static void syncUser(XWikiDocument userProfile, Map<String, Object> casAttributes, XWikiContext context)
        throws XWikiException
    {
        // check if we have to create the user
        XWikiCASConfig config = XWikiCASConfig.getInstance();

        if (userProfile.isNew() || config.getCASParam("cas_update_user", "0", context).equals("1")) {

            LOGGER.debug("CAS attributes will be used to update XWiki attributes.");

            if (casAttributes == null) {
                LOGGER.error("Can't find any attributes");
            }

            if (userProfile.isNew()) {
                LOGGER.debug("Creating new XWiki user based on CAS attributes.");

                Map<String, String> userMappings = config.getUserMappings(context);

                Map<String, String> map = new HashMap<String, String>();
                if (casAttributes != null) {
                    for (Map.Entry<String, String> entry : userMappings.entrySet()) {
                        Object value = casAttributes.get(entry.getKey());
                        if (value != null && value instanceof String)
                            map.put(entry.getValue(), (String) value);
                    }
                }

                // Mark user active
                map.put("active", "1");

                context.getWiki().createUser(userProfile.getDocumentReference().getName(), map, context);

                LOGGER.debug("New XWiki user created: [{}]", userProfile.getDocumentReference());

            } else {

                LOGGER.debug("Updating existing user with CAS attributes");

                try {
                    Map<String, String> userMappings = config.getUserMappings(context);

                    BaseClass userClass = context.getWiki().getUserClass(context);
                    BaseObject userObj = userProfile.getXObject(userClass.getDocumentReference());

                    LOGGER.debug(
                        "Start synchronization of CAS profile with existing user profile based on mapping [{}]",
                        userMappings);

                    Map<String, String> map = new HashMap<String, String>();

                    if (casAttributes != null) {
                        for (Map.Entry<String, String> entry : userMappings.entrySet()) {
                            Object value = casAttributes.get(entry.getKey());
                            if (value != null && value instanceof String) {
                                String objValue = userObj.getStringValue(entry.getValue());
                                if (objValue == null || !objValue.equals(value)) {
                                    map.put(entry.getValue(), (String) value);
                                }
                            }
                        }
                    }

                    boolean needsUpdate = false;
                    if (!map.isEmpty()) {
                        userClass.fromMap(map, userObj);
                        needsUpdate = true;
                    }

                    if (needsUpdate) {
                        context.getWiki().saveDocument(userProfile, "Synchronized user profile with CAS server", true,
                            context);
                    }
                } catch (XWikiException e) {
                    LOGGER.error("Failed to synchronise user's informations", e);
                }
            }
        }
    }

    /**
     * Synchronize user XWiki membership with it's CAS membership.
     * 
     * @param xwikiUserName the name of the user.
     * @param casGroups the CAS groups of the user.
     * @param createuser indicate if the user is created or updated.
     * @param context the XWiki context.
     * @throws XWikiException error when synchronizing user membership.
     */
    public static void syncGroupsMembership(String xwikiUserName, List<String> casGroups, boolean createuser,
        XWikiContext context) throws XWikiException
    {
        XWikiCASConfig config = XWikiCASConfig.getInstance();

        // got valid group mappings
        Map<String, Set<String>> groupMappings = config.getGroupMappings(context);

        // update group membership, join and remove from given groups
        // sync group membership for this user
        if (groupMappings.size() > 0) {

            LOGGER.debug("Updating group membership for the user [{}]", xwikiUserName);

            Collection<String> xwikiUserGroupList =
                context.getWiki().getGroupService(context).getAllGroupsNamesForMember(xwikiUserName, 0, 0, context);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("The user belongs to following XWiki groups: ");
                for (String userGroupName : xwikiUserGroupList) {
                    LOGGER.debug(userGroupName);
                }
            }

            // go through mapped groups to locate the user
            for (Map.Entry<String, Set<String>> entry : groupMappings.entrySet()) {
                String xwikiGroupName = entry.getKey();
                Set<String> groupCASSet = entry.getValue();

                if (xwikiUserGroupList.contains(xwikiGroupName)) {
                    if (!isMemberOfGroups(casGroups, groupCASSet)) {
                        removeUserFromXWikiGroup(xwikiUserName, xwikiGroupName, context);
                    }
                } else {
                    if (isMemberOfGroups(casGroups, groupCASSet)) {
                        addUserToXWikiGroup(xwikiUserName, xwikiGroupName, context);
                    }
                }
            }
        }
    }

    /**
     * Test if at least one item of casGroups belongs to the groupCASSet
     * 
     * @param casGroups groups of user from CAS
     * @param groupCASSet set of CAS group in group mapping
     * @return
     */
    private static boolean isMemberOfGroups(List<String> casGroups, Set<String> groupCASSet)
    {
        for (String group : casGroups) {
            if (groupCASSet.contains(group))
                return true;
        }
        return false;
    }

    /**
     * Add user name to provided XWiki group.
     * 
     * @param xwikiUserName the full name of the user.
     * @param groupName the name of the group.
     * @param context the XWiki context.
     */
    private static void addUserToXWikiGroup(String xwikiUserName, String groupName, XWikiContext context)
    {
        try {
            LOGGER.debug("Adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);

            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get document representing group
            XWikiDocument groupDoc = context.getWiki().getDocument(groupName, context);

            synchronized (groupDoc) {
                // Add a member object to document
                BaseObject memberObj = groupDoc.newXObject(groupClass.getDocumentReference(), context);
                Map<String, String> map = new HashMap<String, String>();
                map.put(XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                groupClass.fromMap(map, memberObj);

                // If the document is new, set its content
                if (groupDoc.isNew()) {
                    groupDoc.setSyntax(Syntax.XWIKI_2_0);
                    groupDoc.setContent("{{include document='XWiki.XWikiGroupSheet' /}}");
                }

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }

            LOGGER.debug("Finished adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);
        } catch (Exception e) {
            LOGGER.error("Failed to add a user [{}] to a group [{}]", new Object[] {xwikiUserName, groupName, e});
        }
    }

    /**
     * Remove user name from provided XWiki group.
     * 
     * @param xwikiUserName the full name of the user.
     * @param groupName the name of the group.
     * @param context the XWiki context.
     */
    private static void removeUserFromXWikiGroup(String xwikiUserName, String groupName, XWikiContext context)
    {
        try {
            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get the XWiki document holding the objects comprising the group
            // membership list
            XWikiDocument groupDoc = context.getWiki().getDocument(groupName, context);

            synchronized (groupDoc) {
                // Get and remove the specific group membership object for the
                // user
                BaseObject groupObj =
                    groupDoc.getXObject(groupClass.getDocumentReference(), XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                groupDoc.removeXObject(groupObj);

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }
        } catch (Exception e) {
            LOGGER.error("Failed to remove a user from a group " + xwikiUserName + " group: " + groupName, e);
        }
    }

    /**
     * @param name the name to convert.
     * @return a valid XWiki user name:
     *         <ul>
     *         <li>Remove '.'</li>
     *         </ul>
     */
    public static String getValidXWikiUserName(String name)
    {
        return name.replace(XWIKI_SPACE_NAME_SEP, "");
    }

}
