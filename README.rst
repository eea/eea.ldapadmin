Eionet roles editor
===================

https://svn.eionet.europa.eu/projects/Zope/ticket/3823

Installation
------------
Place ``eea.ldapadmin`` in eggs and zcml sections of your
zope instance.

Create an empty dir, e.g. var/log/ldap/, and copy config.yaml.sample
(provided next to this readme) to config.yaml in this directory.
Configure user dn and password to bind with. The user dn
should belong to a user able to request unlimited size ldap results.

Set LDAP_DISK_STORAGE environment variable to the path of the former
mentioned empty dir::

    environment-vars =
        LDAP_DISK_STORAGE ${buildout:directory}/var/log/ldap/
        FORUM_URL http://forum.eionet.europa.eu

FORUM_URL is used to link to profile overview.
Also, add this part which will generate a script that can
dump an sqlite copy of the configured branches in config.yaml::

    parts =
        ldapdump
    
    [ldapdump]
    recipe = zc.recipe.egg
    eggs = eea.ldapadmin
    arguments = "${buildout:directory}/var/log/ldap/"

Make sure the path in ``arguments`` is the same you provided
for LDAP_DISK_STORAGE.

From ZMI you can now add an `Eionet Roles Editor` object.

Although done on the fly at first access, you can also configure a cyclic
sync of the country lists with EEA Data Service. Run this in a cron command:
LDAP_DISK_STORAGE=/same/path/here bin/update_countries


The Eionet Profile Overview
----------------------------
The `endpoints` part of config.yaml (see sample in root) contains a list
of Eionet services and credentials to receive local info about users, on those
platforms. Those are basically Zope users with permission to request that URL.