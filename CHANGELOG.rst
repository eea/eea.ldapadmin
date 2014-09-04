1.4.53 (unreleased)
------------------------

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

