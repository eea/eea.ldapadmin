from mock import callargs

class Recorder(object):
    def __init__(self):
        self.call_list = []

    def expect(self, *args, **kwargs):
        return_value = kwargs.pop('return_value', None)
        side_effect = kwargs.pop('side_effect', None)
        call_spec = (callargs((args, kwargs)), return_value, side_effect)
        self.call_list.append(call_spec)

    def assert_end(self):
        if self.call_list != []:
            raise AssertionError("Expected calls not realized (%d calls)" %
                                 len(self.call_list))

    def __call__(self, *args, **kwargs):
        if not self.call_list:
            raise AssertionError("Mock object called more times than expected")
        expected_args, return_value, side_effect = self.call_list.pop(0)
        if expected_args != callargs((args, kwargs)):
            raise AssertionError('Expected: %s\nCalled with: %s' %
                                 ((args, kwargs), expected_args))
        if side_effect is not None:
            raise side_effect
        else:
            return return_value
