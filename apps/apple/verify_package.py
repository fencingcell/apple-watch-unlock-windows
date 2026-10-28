# SPDX-License-Identifier: AGPL-3.0-only
"""Fail closed unless this is a real device host with an embedded Watch app."""
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import zipfile

def validate_metadata(host, watch, host_archs, watch_archs):
    for info, platform in [(host, 'iphoneos'), (watch, 'watchos')]:
        executable = info.get('CFBundleExecutable', '')
        if not executable or '/' in executable or '\\' in executable or executable in ('.', '..'):
            raise ValueError('invalid executable name')
        if info.get('DTPlatformName') != platform or info.get('CFBundlePackageType') != 'APPL':
            raise ValueError('requires device application product')
    host_id = host.get('CFBundleIdentifier', '')
    if not host_id or not watch.get('CFBundleIdentifier', '').startswith(host_id + '.'):
        raise ValueError('invalid nested bundle identity')
    if watch.get('WKCompanionAppBundleIdentifier') != host_id or watch.get('WKApplication') is not True:
        raise ValueError('missing single-target Watch application/companion identity')
    if set(host_archs) != {'arm64'} or not watch_archs or not set(watch_archs) <= {'arm64', 'arm64_32'}:
        raise ValueError('unexpected device executable architectures')

def package(host, output):
    watch = host / 'Watch' / 'Watch.app'
    if not watch.is_dir(): raise ValueError('Host.app/Watch/Watch.app missing')
    if (host / 'PlugIns' / 'Watch.app').exists(): raise ValueError('Watch app misplaced as extension')
    infos, architectures = [], []
    for app in (host, watch):
        with (app / 'Info.plist').open('rb') as f: info = plistlib.load(f)
        executable = info.get('CFBundleExecutable', '')
        if not executable or Path(executable).name != executable: raise ValueError('invalid executable')
        binary = app / executable
        if not binary.is_file(): raise ValueError('missing executable')
        archs = subprocess.check_output(['xcrun', 'lipo', '-archs', str(binary)], text=True).split()
        infos.append(info); architectures.append(archs)
    validate_metadata(*infos, *architectures)
    output.mkdir(parents=True, exist_ok=True)
    ipa = output / 'WatchLogin-unsigned.ipa'
    with zipfile.ZipFile(ipa, 'w', zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(host.rglob('*')):
            if source.is_symlink(): raise ValueError('unexpected application symlink')
            if source.is_file():
                if source.name == 'embedded.mobileprovision': raise ValueError('unexpected provisioning profile')
                archive.write(source, Path('Payload/Host.app') / source.relative_to(host))
    report = {'state': 'unsigned device build; installation and wearer authentication untested', 'bundles': [i['CFBundleIdentifier'] for i in infos], 'architectures': architectures}
    (output / 'package-check.json').write_text(json.dumps(report, indent=2) + '\n')
    sums = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != 'SHA256SUMS':
            sums.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name)
    (output / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__': package(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
