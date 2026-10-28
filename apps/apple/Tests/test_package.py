# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verify_package', Path(__file__).parents[1] / 'verify_package.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class PackageTests(unittest.TestCase):
    def metadata(self):
        return ({'CFBundleIdentifier': 'org.watchlogin.prototype', 'CFBundleExecutable': 'Host', 'CFBundlePackageType': 'APPL', 'DTPlatformName': 'iphoneos'},
                {'CFBundleIdentifier': 'org.watchlogin.prototype.watch', 'CFBundleExecutable': 'Watch', 'CFBundlePackageType': 'APPL', 'DTPlatformName': 'watchos', 'WKApplication': True, 'WKCompanionAppBundleIdentifier': 'org.watchlogin.prototype'})

    def test_device_bundle_links_and_architectures(self):
        host, watch = self.metadata()
        module.validate_metadata(host, watch, ['arm64'], ['arm64_32'])

    def test_wrong_platform_links_or_product_rejected(self):
        host, watch = self.metadata()
        for field, value in [('DTPlatformName', 'watchsimulator'), ('WKApplication', False), ('WKCompanionAppBundleIdentifier', 'other'), ('CFBundleIdentifier', 'other.watch'), ('CFBundlePackageType', 'XPC!'), ('CFBundleExecutable', '../outside')]:
            changed = dict(watch); changed[field] = value
            with self.assertRaises(ValueError): module.validate_metadata(host, changed, ['arm64'], ['arm64_32'])
        for arch in [['x86_64'], ['arm64', 'x86_64'], []]:
            with self.assertRaises(ValueError): module.validate_metadata(host, watch, ['arm64'], arch)
        host['DTPlatformName'] = 'iphonesimulator'
        with self.assertRaises(ValueError): module.validate_metadata(host, watch, ['arm64'], ['arm64_32'])

if __name__ == '__main__': unittest.main()
