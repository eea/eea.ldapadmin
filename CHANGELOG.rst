1.5.34 (unreleased)
------------------------

1.5.33 (2019-11-26)
------------------------
* fixes for the new branch of 'observing countries' [dumitval]

1.5.32 (2019-11-21)
------------------------
* propper way of getting user id [dumitval]

1.5.31 (2019-11-07)
------------------------
* removed some version pins for zope 2.13 compatibility [dumitval]

1.5.30 (2019-10-04)
------------------------
* javascript bugfix [dumitval]

1.5.29 (2019-06-19)
------------------------
* remove mail server dialogue from email validation [dumitval]

1.5.28 (2019-05-16)
------------------------
* fix for organisations member listing in case of deleted users [dumitval]

1.5.27 (2019-03-07)
------------------------
* handle SparqlException on countries import [dumitval]

1.5.26 (2019-03-06)
------------------------
* ldap agent uses bind in several locations [dumitval]

1.5.25 (2019-03-05)
------------------------
* once a day update of the  country code to country name mapping [dumitval]

1.5.24 (2018-10-15)
------------------------
* bugfix in PCP setting [dumitval]

1.5.23 (2018-10-12)
------------------------
* fix PCP setting for the ajax-loaded nrc listing [dumitval]

1.5.22 (2018-09-18)
------------------------
* force two letter country code at the beginning of the org id
  (only at creation) [dumitval]
* handle unicode characters in the id field when creating organisations
  [dumitval]

1.5.21 (2018-08-23)
------------------------
* load nrc listing with ajax to avoid server timeout refs #97788 [dumitval]

1.5.20 (2018-08-08)
------------------------
* handle duplicate org ID when creating organisations [dumitval]

1.5.19 (2018-06-29)
------------------------
* Full name of created user in email notification [dumitval]
* handle ldap security limitation for main admin user
  (in test ldap the Admin ldap user cannot list all users anymore) [dumitval]

1.5.18 (2018-06-04)
------------------------
* use secondary ldap auth for all_organisations if needed [dumitval]
* updated config example with ldaps port [dumitval]

1.5.17 (2018-02-09)
------------------------
* bugfix IE on bulk user creation refs #82360 [dumitval]

1.5.16 (2018-02-05)
------------------------
* updated dependency to unidecode to v.1.0.22 [dumitval]

1.5.15 (2017-10-06)
------------------------
* move the LDAP log patch to Products.LDAPUserFolder 2.24-edw2 [dumitval]

1.5.14 (2017-10-05)
------------------------
* extend info in the LDAP error log [dumitval]

1.5.13 (2017-10-04)
------------------------
* bugfix in connect method [dumitval]

1.5.12 (2017-10-03)
------------------------
* change log type for LDAP errors [dumitval]

1.5.11 (2017-10-03)
------------------------
* patch LDAPUserFolder to log bind and connect errors [dumitval]

1.5.10 (2017-06-29)
------------------------
* organisation editor's change id now checks for correct characters [dumitval]

1.5.09 (2017-06-06)
------------------------
* Prepare password-reset for password constraints [dumitval]

1.5.08 (2017-01-25)
------------------------
* use eionet for from email domain [nituacor]

1.5.07 (2017-01-18)
------------------------
* use the new field reasonToCreate instead of destinationIndicator [dumitval]

1.5.06 (2016-12-21)
------------------------
* there is no need for access token, we use acl_users [nituacor]

1.5.05 (2016-12-21)
-------------------
* Task: API entrypoint for EIONET LDAP command line scripts
  - added ApiTool to expose methods to be called remote
  - each call must provide an access token
  [chiridra #80115]

1.5.04 (2016-11-23)
------------------------
* bugfix in selectize initialisation [dumitval]

1.5.03 (2016-11-23)
------------------------
* remove option to add own item to selectize list [dumitval]

1.5.02 (2016-11-22)
------------------------
* add os environ to zope environment [dumitval]

1.5.01 (2016-11-18)
------------------------
* full name native and search helper available to nfps and bulk import [dumitval]

1.5.00 (2016-11-14)
------------------------
* bugfix in get country id for NFPs [dumitval]

1.4.99 (2016-10-27)
------------------------
* fix crash when the awp link is called without mandatory argument [dumitval]

1.4.98 (2016-10-26)
------------------------
* bugfix in nrc editing (ref: full_name_native) [dumitval]

1.4.97 (2016-10-07)
------------------------
* wording change in Reportnet AWP administration [dumitval]

1.4.96 (2016-10-03)
------------------------
* bugfix in ckecking manager permission [dumitval]

1.4.95 (2016-10-03)
------------------------
* add organisation name in national language [dumitval]
* make organisation, phone number and reason to create the account
  mandatory [dumitval]
* removed uid and password from excel template of bulk user creation
  [dumitval]
* add reportnet-awp branch to NFP managed roles [dumitval]
* changed validate_email version dependency [dumitval]
* add support for the edw version of validate_email [dumitval]
* add permission to Zope managers to view nrc administration [dumitval]
* add Department column in nrc administration [dumitval]
* add department to the LDAP fields [dumitval]
* add name in native language and search helper to user attributes [dumitval]

1.4.94 (2016-04-04)
------------------------
* handle weird limitation of ldap field destinationIndicator [dumitval]
* handling for missing org and user_id in nfp user edit page [dumitval]
* fix typo in roles_filter_form [dumitval]

1.4.93 (2016-02-26)
------------------------
* allow country filtering of organisations [dumitval]

1.4.92 (2016-02-23)
------------------------
* handle missing id in organisations editor [dumitval]

1.4.91 (2015-11-04)
------------------------
* restore roles only on demand (when enabling users) [dumitval]

1.4.90 (2015-11-02)
------------------------
* fix creation from excel (crashes with blanks in user name and
  uppercase letters in email [dumitval]

1.4.89 (2015-10-27)
------------------------
* add option to skip extended email validation to user edit [dumitval]

1.4.88 (2015-08-21)
------------------------
* Bug fix: remove pdb line
  [tiberich #28208]

1.4.87 (2015-08-10)
------------------------
* Bug fix: also update the COUNTRIES dict when loading countries from disk
  [tiberich #27908]

1.4.86 (2015-08-07)
------------------------
* Bug fix: In bulk import users, also add users to desired organisation
  [tiberich #27767]

1.4.85 (2015-07-21)
------------------------
* Bug fix: properly interogate NFP role when determining NFPs for user
  [tiberich #27547]
* Bug fix: fix bug in loading countries in NFP tool
  [tiberich #27547]

1.4.84 (2015-06-26)
------------------------
* Bug fix: fix editing of users in organisation context
  [tiberich #26967]
* Bug fix: fixes to auto-disabling users. It can now be used in production
* Feature: added a script that can be run from cron that can trigger user
  autodisabling. Run as ``bin/zope-instance run bin/auto_disable_users``
  [tiberich 20559]

1.4.83 (2015-06-17)
------------------------
* Bug fix: fix a case when adding user and email validatino didn't fail
  [tiberich #26590]

1.4.82 (2015-06-17)
------------------------
* Bug fix: check if validate_email raises error, in case email server can't be contacted
* Bug fix: added pyDNS and validate_email to dependencies

1.4.81 (2015-06-08)
------------------------
* Bug fix: fix get_nfps_for_country method, it was not updated for API changes
  [tiberich #24566]

1.4.80 (2015-06-05)
------------------------
* Feature: when creating a user, validate his email with email_validate.
  [tiberich #18815]

1.4.79 (2015-05-25)
------------------------
* Feature: also email the NFP that created the user with a confirmation email
  about user creation
  [tiberich #23076]
* Change: because emails of disabled users are no longer changed, adjust
  users_admin and password reset tool accordingly
  [tiberich #24321]

1.4.78 (2015-05-14)
------------------------
* Feature: enable a changelog for organisations, which includes: adding/removing members
  editing details of organisation (no details here, though), and renaming the organisation
  [tiberich #20663]
* Bug fix: see if user has the Eionet edit extended roles permission before showing
  extended roles functionality
  [tiberich #22472]

1.4.77 (2015-05-06)
------------------------
* changed permission for search_users [dumitval]

1.4.76 (2015-04-22)
------------------------
* bugfix in UID generation [dumitval]

1.4.75 (2015-04-15)
------------------------
* Bug fix: add the can_edit_users method to PasswordReset tool, it is used
  by its index template
  [tiberich]

1.4.74 (2015-04-14)
------------------------
* is_manager replaced by can_edit_users, bound to permission, not role
  [dumitval]

1.4.73 (2015-03-30)
------------------------
* Bug fix: use bind=True for get_ldap_agent; This way the LDAP queries will be sent
  with credentials, and it will get full results for users, instead of restricted results
  [tiberich #24362]
* Bug fix: improve bulk email check form: show emails that are duplicated; convert emails to
  lower case, to detect duplicates
  [tiberich #23187]

1.4.72 (2015-03-24)
------------------------
* Bug fix: fix info message display for edit user form
  [tiberich #23187]
* Change: show a timestamp in info message when disabling/enabling user
  [tiberich #23187]
* Feature: show the original email for a disabled user in edit user page and user search
  [tiberich #23187]

1.4.71 (2015-03-24)
------------------------
* Bug fix: better handling of errors in bulk import users; also report created users
  [tiberich #23187]

1.4.70 (2015-03-23)
------------------------
* Bug fix: added python-dateutil as dependency for autodisable users view
  [tiberich #20559]

1.4.69 (2015-03-23)
------------------------
* Refactor: refactored the bulk user create form. Better readability and debugging. Improved
  error reporting
  [tiberich #23187]
* Feature WIP: added a view page to automatically disable inactive users
  [tiberich #20559]

1.4.68 (2015-03-04)
------------------------
* Bug fix: send a notification email to helpdesk when an account has been created by bulk import
  [tiberich #21233]

1.4.67 (2015-02-13)
------------------------
* Bug fix: show an error message when email is duplicate, on create user page
  [tiberich]

1.4.66 (2015-01-27)
------------------------
* Bugfix related to nfp_has_access [dumitval]

1.4.65 (2015-01-23)
------------------------
* Bug fix: improve pages of extended management of roles
  [tiberich #21218]

1.4.64 (2015-01-15)
------------------------
* Feature: enable extended management of roles
  [tiberich #21218]
* Bug fix: cleanup code to import roles
  [tiberich #21731]
* Bug fix: don't allow disabled users to have their email changed and to recover their password
  [tiberich #22488]

1.4.63 (2014-10-03)
------------------------
* Bug fix: fix label for destinationIndicator field of user account creation form (for NFPs)
  [tiberich #21265]

1.4.62 (2014-10-03)
------------------------
* Change: only show country organisations in the NFP create user page
  [tiberich #21265]

1.4.61 (2014-10-02)
------------------------
* Bug fix: fix bulk creation of accounts with unicode spaces in row values
  [tiberich #21233]
* Bug fix: validate duplicate usernames on account creation
  [tiberich #21233]

1.4.60 (2014-09-26)
------------------------
* allow changing first name on user edit [dumitval]

1.4.59 (2014-09-24)
------------------------
* Feature: added the Reset user action in the user edit page
  [tiberich #9164]

1.4.58 (2014-09-23)
------------------------
* remove 'Status' from user listing in roles [dumitval]

1.4.57 (2014-09-19)
------------------------
* Feature: for the user changelog feature, added the posibility to group LDAP action through an "action id"
  [tiberich #20422]

1.4.56 (2014-09-10)
------------------------
* Bug fix: added the split() method to SimplifiedRole, to fix the
  users_editor code
  [tiberich #20129]

1.4.55 (2014-09-05)
------------------------
* delete method that is not used in CreateUser class [tiberich]
* Removed the username field from the Account creation page for NFP
  [tiberich #20187]

1.4.54 (2014-09-05)
------------------------
* added missing method on CreateUser class [tiberich]

1.4.53 (2014-09-04)
------------------------
* added missing method on CreateUser class [dumitval]

1.4.52 (2014-09-01)
------------------------
* Bug fix: use orgs_in_country method from view code instead of context
  [tiberich #20187]

1.4.51 (2014-09-01)
------------------------
* Bug fix: use info from naaya.ldapdump if LDAP_DISK_STORAGE is not set
  [tiberich #20187]

1.4.50 (2014-08-29)
------------------------
* Bug fix: implement missing method in nrc_nfp
  [tiberich #20187]

1.4.49 (2014-08-29)
------------------------
* Bug fix: fix duplicate email checking in account creation by NFPs
  [tiberich #20187, #20880]

1.4.48 (2014-08-29)
------------------------
* Bug fix: added custom template for email message sent on account creation by NFP
  [tiberich #20187]

1.4.47 (2014-08-28)
------------------------
* Bug fix: properly allow editing user accounts by NFPs
  [tiberich #20870]

1.4.46 (2014-08-28)
------------------------
* Bug fix: added information about the NFP to create the account, in the
  helpdesk email that is sent when NFPs create new accounts
  [tiberich #20187]

1.4.45 (2014-08-27)
------------------------
* Bug fix: allow changing the last_name of a user, in the account edit form
  [tiberich #20788]
* Bug fix: allow changing the user organisation when 'o' field value has a
  valid user organisation, but it's not really assigned to the organisation
  as a member
  [tiberich #20835]
* Bug fix: fix creating users by NFPs when send confirmation email is checked
  [tiberich #20187]

1.4.44 (2014-08-25)
------------------------
* Add the create_user page to nfp_nrc objects to allow them to create users
  [tiberich #20187]

1.4.43 (2014-08-20)
------------------------
* allow nfps to create Eionet accounts from nfp-eionet portal
  [dumitval, tiberich #20187]

1.4.42 (2014-08-07)
------------------------
* Bug fix: also show the organisation select dropdown in the user creation form
  [tiberich]

1.4.41 (2014-08-06)
------------------------
* Bug fix: Fix styling of permissions accordion in roles_browse.zpt. Open link to
  Forum/Projects in new window
  [tiberich #20522]
* Feature: allow filtering users by disabled status in users listing of Roles Editor -
  All members page
  [tiberich #20390]

1.4.40 (2014-07-31)
------------------------
* Bug fix: fix formatting of buttons in role editor page
  [tiberich #20522]
* Feature: show links to Projects and Forum role overviews in the location section
  [tiberich #20522]

1.4.39 (2014-07-29)
------------------------
* Bug fix: use better security to decide when to show owners and permitted senders information
  [tiberich #18817]

1.4.38 (2014-07-29)
------------------------
* Bug fix: put a link to the person's email in the listing of roles, for their owners
  [tiberich #18817]

1.4.37 (2014-07-28)
------------------------
* Bug fix: only show permitted senders and owners to the authenticated visitors
  [tiberich #18817]

1.4.36 (2014-07-25)
------------------------
* Feature: show owners and permittedSenders in subrole listing in role page overview
  [tiberich #18817]

1.4.35 (2014-07-15)
------------------------
* Feature: added an accordion to show explicitely where each role/subrole has permissions
  [tiberich #19234]

1.4.34 (2014-07-15)
------------------------
* Bug fix: fix user account editing when the credentials are not ok with LDAP server
  [tiberich #19143]

1.4.33 (2014-07-03)
------------------------
* Bug fix: remove all organisations for a user before changing his organisation
  [tiberich #19143]

1.4.32 (2014-07-03)
------------------------
* Change: show only the "end role" when a user is added to a role in the nrc screen,
  instead of showing the entire hierarchy of roles
  [tiberich #19143]

1.4.31 (2014-07-02)
------------------------
* Bug fix: show parens in organisation selection list for users edit forms
  [tiberich #19143]

1.4.30 (2014-07-02)
------------------------
* Bug fix: fix NRC table (id of link, add org id in parens, show proper message at top)
  [tiberich #19143]

1.4.29 (2014-07-02)
------------------------
* Bug fix: handle EEA as a separate country
  [tiberich #19143]

1.4.28 (2014-07-02)
------------------------
* Bug fix: when member belongs to an organisation, use the organisation
  membership instead of the 'o' field from LDAP, to show their
  membership

1.4.27 (2014-07-02)
------------------------
* Allow nfp for eea to edit eu and int organisations [dumitval]

1.4.26 (2014-07-02)
------------------------
* Use the template provided by the Naaya Groupware, if the Zope server is a
  groupware application
  [tiberich #19143]

1.4.25 (2014-07-01)
------------------------
* Return correct message when trying to reset password for
  disabled@eionet... [dumitval]

1.4.24 (2014-06-30)
------------------------
* Ignore disabled@eionet.europa.eu as email for reset password [dumitval]

1.4.23 (2014-06-30)
------------------------
* Bug fix: renamed builtin id() to user_id
  [tiberich]

1.4.22 (2014-06-30)
------------------------
* Bug fix: set colander version to 0.9.7

1.4.21 (2014-06-30)
------------------------
* Bug fix: lower version for deform and colander

1.4.20 (2014-06-27)
------------------------
* Show all organisations also for NFPs when accessed outside the
  nfp-eionet IG [dumitval]
* Fix eea organisations filtering (nfp-eionet ig) [dumitval]

1.4.19 (2014-06-26)
------------------------
* Added the ability to import an XLS file to perform batch changes to roles
  [tiberich #20140]
* Show all organisations also for NFPs when accessed outside the
  nfp-eionet IG [dumitval]
* Fix eea organisations filtering (nfp-eionet ig) [dumitval]

1.4.18 (2014-06-24)
------------------------
* added handling for deleted users when editing role owners [dumitval]

1.4.17 (2014-06-24)
------------------------
* removed merged columns from a dataTable [dumitval]

1.4.16 (2014-06-20)
------------------------
* added expiration time information in the password reset email [dumitval]
* refraze confirmation email [dumitval]

1.4.15 (2014-06-20)
------------------------
* adapted the email templates (confirmation and password reset) [dumitval]

1.4.14 (2014-06-20)
------------------------
* Auto-send reset password email to new users [dumitval]

1.4.13 (2014-06-18)
------------------------
* Changed style in Excel generation (again for newline display) [dumitval]

1.4.12 (2014-06-18)
------------------------
* Bugfix in Excel generation (added Windows-style new-line characters) [dumitval]

1.4.11 (2014-06-06)
------------------------
* Bug fix: show the full path for a location where role has permission, in the roles overview
  [tiberich #19234]

1.4.10 (2014-06-04)
------------------------
* Bug fix: look in zodb root for Groupware sites, to show where the role is being used
  [tiberich #19234]

1.4.9 (2014-05-21)
------------------------
* bugfix in email sending [dumitval]

1.4.8 (2014-05-20)
------------------------
* bugfix in email sending [dumitval]

1.4.7 (2014-05-20)
------------------------
* Send confirmation and password emails on bulk user creation [dumitval]
* Changed wording in the password reset form (Recover --> Reset) [dumitval]

1.4.6 (2014-04-17)
------------------------
* Use Excel format for bulk_create_user [dumitval]
* removed csv export functionality [dumitval]
* Update bulk_create_user (new mandatory fields, import valid rows) [dumitval]
* Label changes ("Name of user" --> "Search for") [dumitval]

1.4.5 (2014-03-07)
------------------------
* make the redirect to password reset also from eionet_profile [dumitval]

1.4.4 (2014-03-07)
------------------------
* added a custom description for managers in the password reset tool [dumitval]

1.4.3 (2014-03-07)
------------------------
* redirect to password reset when changing user password [dumitval]
* Feature: have a statistics page to report number of users created per year
  [tiberich #18676]
* WIP: Feature: show where a group role is granted in all NFPs
  [tiberich #13911]

1.4.2 (2014-01-15)
------------------------
* Dont overwrite passwords with empty strings [dumitval]

1.4.1 (2013-11-21)
------------------------
* Feature: allow showing members at a particular date for a role
  [tiberich #16665]
* Feature: allow export of organisation details + member list in Excel format
  [tiberich #17369]
* Feature: allow export of all organisations in a country by an NFP
  [tiberich #17369]
* Feature: added the email/mail field to the EIONET organisation schema
  [tiberich #17369]

1.4.0 (2013-10-29)
------------------------
* disabled users cannot be role owners [dumitval]
* disabled users cannot be added to an organisation [dumitval]
* Conform to API changes in eea.usersdb
  [tiberich #16665]

1.3.9 (23-10-2013)
----------------------
* Allow enabling/disabling users
  [tiberich #17085]

1.3.8 (2013-10-17)
----------------------
* name and country are mandatory for organisations [dumitval]

1.3.7 (2013-10-11)
----------------------
* bugfix: orgs_editor should not be Naaya dependent [dumitval]

1.3.6 (2013-10-10)
----------------------
* message for deleted ldap users (ldap roles listing) [dumitval]

1.3.5 (2013-10-10)
----------------------
* edit organisation ldap data [dumitval]
* messages instead of Unauthorized [dumitval]
* organisation rename only available to managers [dumitval]

1.3.4 (2013-10-09)
----------------------
* bugfix in CommonTemplateLogic.is_authenticated [dumitval]

1.3.3 (2013-10-09)
----------------------
* bugfix in CommonTemplateLogic.is_authenticated [dumitval]

1.3.2 (2013-10-09)
----------------------
* possibility for NFPs to edit the orgs in their country [dumitval]

1.3.1 (2013-09-05)
----------------------
* #15628; show country and name of orgs in org editor index [simiamih]

1.3.0 (2013-08-06)
----------------------
* #15266; add/edit forms - selecting country [simiamih]
* feature: eionet profile overview #9607 [simiamih]

1.2.2 (2013-06-17)
----------------------
* clicking on existing PCP unsets it in NFP-NRC tool [simiamih]

1.2.1 (2013-06-14)
----------------------
* feature: #14597 NFPs can now set PCP for each NRC role [simiamih]

1.2 (2013-06-13)
----------------------
* fix: using secondary login dn [simiamih]

1.1.1 (2013-06-12)
----------------------
* feature: #14597 NFPs are able to change profile info of NRCs [simiamih]
* secondary admin login dn for #14597 [simiamih]
* #14557 improved text in welcome email [simiamih]

1.1.0 (2013-02-21)
----------------------
* #9181 - add real-time table with similarities [mihaitab]
* #13609; csv export replaced by xls export [simiamih]
* #9181 - find similarities when creating new account [mihaitab]
* #9994 - update UI messages on owner add/remove [simiamih]
* dump_ldap - script for creating local sqlite of users objs [simiamih]
* #13854 Organisation validation [mihaitab]
* #9231 Mark specific memberships in roles [simiamih]
* #10254 allow alphanumerical characters for role id [simiamih]

1.0.3 (2012-11-30)
----------------------
* feature: #9497 include specific subrole in all members
  view/export [simiamih]

1.0.2 (2012-10-29)
----------------------
* removed Circa encoding validation [simiamih]
* email payloads where not encoded [simiamih]
* include encoding BOM for csv files [simiamih]

1.0.1 (2012-08-29)
----------------------
* feature: edit role description (name) [simiamih]
* typo in email_change_password.zpt [simiamih]
* using the new users_rdn config in eea.usersdb 1.1.0 [simiamih]

1.0.0 (2012-07-12)
----------------------
* Send users' password by email when creating an account or changing
  account password [bogdatan]
* bugfix: accept non-latin chars in search fields [simiamih]
* owners can delete empty roles [simiamih]
* IMailDelivery defaults to "naaya-mail-delivery" named utility [simiamih]
* customizing NETWORK_NAME from environ (e.g. Eionet, SINAnet) [simiamih]

