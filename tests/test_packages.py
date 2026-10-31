import os
import unittest
from dataclasses import replace
from unittest.mock import patch
from ascent_core.packages import (
    BASE, PLUS, PLUS_PROVIDER, Context, Installed, PackageError,
    plan_install, authorize_execution, require_extension_removal,
)


def widget(package='mapster', **extra):
    return dict(package_id=package, version='1.0.0', kind='widget', family='mapster', **extra)


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.base = Context('0.43.45')
        self.plus = replace(self.base, verified_extensions=frozenset((PLUS,)),
                            loaded_providers=frozenset((PLUS_PROVIDER,)))

    def refuses(self, code, call, *args):
        with self.assertRaises(PackageError) as caught:
            call(*args)
        self.assertEqual(caught.exception.code, code)

    def test_base_mapping_package_available(self):
        self.assertEqual(plan_install(widget(), self.base).action, 'install')

    def test_private_variant_requires_upgrade_even_if_manifest_omits_requirement(self):
        self.refuses('APPLICATION_UPGRADE_REQUIRED', plan_install, widget('mapster-plus'), self.base)

    def test_product_flag_cannot_supply_an_actual_provider(self):
        with patch.dict(os.environ, {'ASCENT_EDITION': 'industrial', 'ASCENT_PRODUCT': PLUS}):
            self.assertEqual(self.base.product, BASE)
            self.refuses('APPLICATION_UPGRADE_REQUIRED', plan_install, widget('mapster-plus'), self.base)

    def test_receipt_without_loaded_provider_is_insufficient(self):
        context = replace(self.base, verified_extensions=frozenset((PLUS,)))
        self.refuses('APPLICATION_UPGRADE_REQUIRED', plan_install, widget('mapster-plus'), context)

    def test_provider_without_verified_extension_is_insufficient(self):
        context = replace(self.base, loaded_providers=frozenset((PLUS_PROVIDER,)))
        self.refuses('APPLICATION_UPGRADE_REQUIRED', plan_install, widget('mapster-plus'), context)

    def test_verified_upgrade_and_provider_allow_install(self):
        self.assertEqual(plan_install(widget('mapster-plus'), self.plus).action, 'install')

    def test_existing_install_does_not_bypass_execution_dependency(self):
        self.assertTrue(authorize_execution(widget('mapster-plus'), self.plus))
        self.refuses('APPLICATION_UPGRADE_REQUIRED', authorize_execution, widget('mapster-plus'), self.base)

    def test_variant_upgrade_keeps_configuration_family(self):
        state = replace(self.plus, installed_widgets={'mapster': Installed('mapster', '1.2.1', 'mapster')})
        plan = plan_install(widget('mapster-plus'), state)
        self.assertEqual((plan.action, plan.config_namespace, plan.previous_package),
                         ('upgrade_variant', 'mapster', 'mapster'))

    def test_widget_update_and_downgrade_rules(self):
        state = replace(self.base, installed_widgets={'mapster': Installed('mapster', '0.9.0', 'mapster')})
        self.assertEqual(plan_install(widget(), state).action, 'upgrade')
        newer = replace(self.base, installed_widgets={'mapster': Installed('mapster', '2.0.0', 'mapster')})
        self.refuses('DOWNGRADE_BLOCKED', plan_install, widget(), newer)

    def test_data_schema_change_requires_reviewed_migration(self):
        state = replace(self.base, installed_widgets={'mapster': Installed('mapster', '0.9.0', 'mapster')})
        self.refuses('CONFIG_MIGRATION_REQUIRED', plan_install, widget(config_schema=2), state)

    def test_dependency_breaking_application_removal_is_refused(self):
        state = replace(self.plus, installed_widgets={'mapster': Installed('mapster-plus', '1.0.0', 'mapster')})
        self.refuses('DEPENDENT_PACKAGES_INSTALLED', require_extension_removal, PLUS, state)

    def test_app_version_and_loader_api_enforced(self):
        self.refuses('APP_UPDATE_REQUIRED', plan_install, widget(min_app_version='1.0.0'), self.base)
        self.refuses('LOADER_API_MISMATCH', plan_install, widget(loader_api=99), self.base)

    def test_reserved_identity_cannot_masquerade_as_application_upgrade(self):
        self.refuses('RESERVED_PACKAGE_INVALID', plan_install,
                     dict(package_id=PLUS, version='1.0.0', kind='widget', family=BASE), self.base)

    def test_client_edition_claim_is_not_a_manifest_field(self):
        self.refuses('MANIFEST_INVALID', plan_install, widget('mapster-plus', edition='industrial'), self.base)


if __name__ == '__main__':
    unittest.main()
