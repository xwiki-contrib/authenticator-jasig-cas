Authenticate user on main wiki based on Jasig CAS server. It creates XWiki users if they have never logged in before and synchronizes membership to XWiki groups based on membership to CAS group field mapping. It supports CAS 2.0 and SAML 1.1 protocol. SAML protocol can be used for attributes and group membership synchronization.

# Configuration (xwiki.cfg)

	# CAS authentication
	xwiki.authentication.authclass=org.xwiki.contrib.authentication.cas.XWikiCASAuthenticator

	# CAS server url (i.e. https://localhost:8443/cas)
	xwiki.authentication.cas.server=https://localhost:8443/cas

	# possible values are CAS20 or SAML11
	xwiki.authentication.cas.protocol=SAML11

	# user not authorized page (i.e. /bin/view/XWiki/XWikiCASAccessDenied). If not set a HTTP status 401 is returned.
	#xwiki.authentication.cas.access_denied_page=/bin/view/XWiki/XWikiCASAuthFailed

	# (only SAML11) mapping between XWiki user profile values and CAS attributes. Example (xwiki-attribute=cas-attribute,...)
	xwiki.authentication.cas.fields_mapping=last_name=lastName,first_name=firstName,email=email

	# 0 or 1 if create XWiki user after log in
	xwiki.authentication.cas.create_user=1

	# 0 or 1 if update user attributes after every log in
	xwiki.authentication.cas.update_user=1

	# (only SAML11) CAS attribute name which contains group membership
	xwiki.authentication.cas.group_field=roles

	# (only SAML11) Maps XWiki groups to CAS groups, separator is "|".
	xwiki.authentication.cas.group_mapping=XWiki.XWikiAdminGroup=cn=AdminRole,ou=groups,o=domain,c=com|\
                                         XWiki.CASUsers=ou=groups,o=domain,c=com|\
                                         XWiki.Organisation=cn=Org1,ou=groups,o=domain,c=com

# Install

* Copy this authenticator jar file into WEB-INF/lib
* Download CAS Client for Java 3.1 from http://downloads.jasig.org/cas-clients/cas-client-3.2.1-release.tar.gz and extract cas-client-core-3.2.1.jar and xmlsec-1.3.0.jar into WEB-INF/lib
* If you want to use SAML11 protocol you must also download Java OpenSAML 1.1 library from http://shibboleth.net/downloads/java-opensaml/archive/1.1b/opensaml-java-1.1b.tar.gz and extract opensaml-1.1.jar into WEB-INF/lib
* Setup xwiki.cfg

# TODO

* Logout from CAS is not implemented yet. As workaround you could change menuview.vm in your skin. Change the generation of logout url from
	
	\#set ($logouturl = $xwiki.getURL('XWiki.XWikiLogout', 'logout', "xredirect=$escapetool.url($xwiki.relativeRequestURL)"))
	
	to something like
	
	\#set ($logouturl = $xwiki.getURL('XWiki.XWikiLogout', 'logout', "xredirect=$escapetool.url('https://localhost:8443/cas/logout')"))

