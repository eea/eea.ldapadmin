from ldap import (SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE, VERSION3,
                  NO_SUCH_OBJECT, ALREADY_EXISTS, NOT_ALLOWED_ON_NONLEAF,
                  NO_SUCH_ATTRIBUTE, OBJECT_CLASS_VIOLATION,
                  TYPE_OR_VALUE_EXISTS,
                  MOD_ADD, MOD_DELETE, RES_ADD, RES_DELETE, RES_MODIFY,
                  RES_BIND)

data = {}

def initialize(url):
    return MockConnection()

class MockConnection(object):
    def search_s(self, query_dn, scope, filterstr=None, attrlist=None):
        # filterstr is currently ignored

        out = []
        dn_set = []
        filters = []

        if scope == SCOPE_BASE:
            if query_dn in data:
                dn_set.append(query_dn)
        elif scope == SCOPE_ONELEVEL:
            for dn in data:
                if dn.endswith(',' + query_dn):
                    if dn[:-len(query_dn)].count(',') == 1:
                        dn_set.append(dn)
        elif scope == SCOPE_SUBTREE:
            if query_dn in data:
                dn_set.append(query_dn)
            for dn in data:
                if dn.endswith(',' + query_dn):
                    dn_set.append(dn)

        for dn in dn_set:
            attrs = {}
            for name, value in data[dn].iteritems():
                assert type(value) is list
                if attrlist is None or name in attrlist:
                    attrs[name] = value
            out.append( (dn, attrs) )

        return out

    def add_s(self, dn, modlist):
        if dn in data:
            raise ALREADY_EXISTS
        if dn.split(',', 1)[1] not in data: # make sure the parent exists
            raise NO_SUCH_OBJECT

        data[dn] = dict(modlist)

        return (RES_ADD, [])

    def delete_s(self, dn):
        for other_dn in data:
            if other_dn.endswith(','+dn):
                raise NOT_ALLOWED_ON_NONLEAF
        del data[dn]
        return (RES_DELETE, [])

    def modify_s(self, dn, modlist):
        assert dn in data
        for action, attr_name, values in modlist:
            if action == MOD_ADD:
                current_values = data[dn].setdefault(attr_name, [])
                if attr_name == 'uniqueMember':
                    if set(values) & set(current_values):
                        raise OBJECT_CLASS_VIOLATION # values must be unique
                current_values.extend(values)
            elif action == MOD_DELETE:
                attr_values = data[dn][attr_name]
                if attr_name == 'uniqueMember':
                    if not set(attr_values) - set(values):
                        raise OBJECT_CLASS_VIOLATION # removing the last member
                for v in values:
                    if v not in attr_values:
                        raise NO_SUCH_ATTRIBUTE
                    attr_values.remove(v)
                if not values:
                    del data[dn][attr_name]
            else:
                assert False, "unknown action %r" % action

        return (RES_MODIFY, [])

    def simple_bind_s(self, bind_dn, bind_pw):
        return (RES_BIND, [])
