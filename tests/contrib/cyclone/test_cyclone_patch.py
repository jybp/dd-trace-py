from ddtrace.contrib.cyclone import patch
from tests.contrib.patch import PatchTestCase


class TestCylconePatch(PatchTestCase.Base):
    __integration_name__ = "cyclone"
    __module_name__ = "cyclone"
    __patch_func__ = patch
    __unpatch_func__ = None

    def assert_module_patched(self, cyclone):
        self.assert_wrapped(cyclone.web.RequestHandler.__init__)
        self.assert_wrapped(cyclone.web.RequestHandler._execute_handler)
        self.assert_wrapped(cyclone.web.RequestHandler.render_string)
        self.assert_wrapped(cyclone.web.RequestHandler.on_finish)
        self.assert_wrapped(cyclone.web.UIModule.render)
        self.assert_wrapped(cyclone.web.UIModule.render_string)
        self.assert_wrapped(cyclone.template.Template.generate)

    def assert_not_module_patched(self, cyclone):
        self.assert_not_wrapped(cyclone.web.RequestHandler.__init__)
        self.assert_not_wrapped(cyclone.web.RequestHandler._execute_handler)
        self.assert_not_wrapped(cyclone.web.RequestHandler.render_string)
        self.assert_not_wrapped(cyclone.web.RequestHandler.on_finish)
        self.assert_not_wrapped(cyclone.web.UIModule.render)
        self.assert_not_wrapped(cyclone.web.UIModule.render_string)
        self.assert_not_wrapped(cyclone.template.Template.generate)

    def assert_not_module_double_patched(self, cyclone):
        self.assert_not_double_wrapped(cyclone.web.RequestHandler.__init__)
        self.assert_not_double_wrapped(cyclone.web.RequestHandler._execute_handler)
        self.assert_not_double_wrapped(cyclone.web.RequestHandler.render_string)
        self.assert_not_double_wrapped(cyclone.web.RequestHandler.on_finish)
        self.assert_not_double_wrapped(cyclone.web.UIModule.render)
        self.assert_not_double_wrapped(cyclone.web.UIModule.render_string)
        self.assert_not_double_wrapped(cyclone.template.Template.generate)