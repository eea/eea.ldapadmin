1.4.3 (unreleased)
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

