Eionet roles editor
===================

https://svn.eionet.europa.eu/projects/Zope/ticket/3823

Installation
------------
For Zope 2.8: make sure the ``eea`` folder is on the Python path, so that
``eea.roleseditor`` can be imported. Copy or symlink the
``Products/EionetRolesEditor`` folder into a Zope product folder (e.g. the
``Products`` folder inside ``INSTANCE_HOME``).

For Zope 2.10 and newer: make sure ``eea.roleseditor`` and
``Products.EionetRolesEditor`` can be imported. Zope will automatically find
and load the product at startup.

From ZMI you can now add an `Eionet Roles Editor` object.

Following configuration is needed in buildout (zope-instance) to properly link
naaya.groupware.profileoverview from eea.ldapadmin.dashboard:
environment-vars =
    FORUM_URL http://forum.eionet.europa.eu
