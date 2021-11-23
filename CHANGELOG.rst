1.0.3-ispra (unreleased)
----------------------
* get email addr from environment variable [dumitval]

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

