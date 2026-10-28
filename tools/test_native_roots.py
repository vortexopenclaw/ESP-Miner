#!/usr/bin/env python3
"""Offline native regression using the release SDK, never a device or socket."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SDK_SHA = '7101770dc6db2667b3c477cc31365dd1acd6db4e'
MBED_SHA = '6cc42afad309e861f4c07e6f106e2ab14a9cb8e5'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idf-path', type=Path, default=os.environ.get('IDF_PATH'))
    parser.add_argument('--output', type=Path, required=True, help='New isolated output directory')
    args = parser.parse_args()
    if not args.idf_path:
        parser.error('--idf-path or IDF_PATH is required')
    sdk = args.idf_path.resolve()
    mbed = sdk / 'components/mbedtls/mbedtls'
    out = args.output.resolve()
    if out.exists():
        parser.error('--output must not exist; earlier evidence is never overwritten')
    out.mkdir(parents=True)
    rows = []

    def run(argv, expected=0):
        argv = list(map(str, argv))
        p = subprocess.run(argv, cwd=out, capture_output=True, text=True)
        with (out / 'commands.log').open('a') as log:
            log.write(repr(argv) + '\n' + p.stdout + p.stderr + '\n')
        if p.returncode != expected:
            raise RuntimeError(f'{argv[0]} exited {p.returncode}, expected {expected}; see commands.log')
        return p.stdout

    for path, sha in [(sdk, SDK_SHA), (mbed, MBED_SHA)]:
        if run(['git', '-C', path, 'rev-parse', 'HEAD']).strip() != sha:
            raise RuntimeError('SDK revision differs from the reviewed release pin')
        if run(['git', '-C', path, 'status', '--porcelain', '--untracked-files=no']).strip():
            raise RuntimeError('SDK tracked sources must be clean')
    for name in ('roots.inc', 'root-identities.json'):
        if (ROOT / 'components/pinned_roots' / name).exists():
            raise RuntimeError('Generate native roots in the build directory, not the source tree')
    fixtures = ROOT / 'tools/native_roots/fixtures'
    if list(fixtures.glob('*emudhra*.pem')):
        raise RuntimeError('Reuse the existing incident archive instead of copied chains')
    manifest = json.loads((fixtures / 'sha256.json').read_text())
    for name, digest in manifest.items():
        data = (fixtures / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f'Fixture checksum mismatch: {name}')
    incident_fixtures = out / 'incident-fixtures'
    incident_fixtures.mkdir()
    archive = ROOT / 'certificates/test/emudhra-chains-2026-10-20.zip'
    if hashlib.sha256(archive.read_bytes()).hexdigest() != '8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95':
        raise RuntimeError('Incident archive checksum mismatch')
    with zipfile.ZipFile(archive) as chains:
        names = [name for name in chains.namelist() if name.endswith('.pem')]
        assert len(names) == 12
        for name in names:
            target = incident_fixtures / Path(name).name
            assert not target.exists()
            target.write_bytes(chains.read(name))
    run([sys.executable, ROOT / 'tools/generate_pinned_roots.py', '--output', out / 'roots.inc'])
    config = out / 'native_config.h'
    config.write_text('#undef MBEDTLS_HAVE_TIME_DATE\n#define MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK\n')
    compat = out / 'compat/mbedtls'
    compat.mkdir(parents=True)
    for header in (mbed / 'tf-psa-crypto/drivers/builtin/include/mbedtls/private').glob('*.h'):
        (compat / header.name).write_text('#include "' + str(header) + '"\n')
    includes = [mbed / 'include', mbed / 'tf-psa-crypto/include',
                mbed / 'tf-psa-crypto/drivers/builtin/include', compat.parent,
                ROOT / 'components/pinned_roots', ROOT / 'tools/native_roots', out]
    # Preserve literal macro quotes and paths containing spaces through CMake.
    flags = ['-DMBEDTLS_THREADING_C', '-DMBEDTLS_THREADING_PTHREAD',
             '-DMBEDTLS_PLATFORM_MEMORY', '-DMBEDTLS_USER_CONFIG_FILE="' + str(config) + '"']
    import shlex
    cflags = ' '.join(shlex.quote(x) for x in [*['-I' + str(p) for p in includes], *flags])
    run(['cmake', '-S', mbed, '-B', out / 'build', '-DENABLE_TESTING=OFF',
         '-DENABLE_PROGRAMS=OFF', '-DGEN_FILES=OFF', '-DMBEDTLS_FATAL_WARNINGS=OFF',
         '-DCMAKE_C_FLAGS=' + cflags])
    run(['cmake', '--build', out / 'build', '--parallel', '8'])
    libs = [out / 'build/library' / ('lib' + n + '.a') for n in ['mbedtls', 'mbedx509', 'mbedcrypto']]
    def compile_probe(source, name, extra=(), helper=True):
        run([os.environ.get('CC', 'cc'), '-O2', '-pthread', *flags,
             *['-I' + str(p) for p in includes], '-I' + str(mbed / 'library'), *extra,
             source, *([ROOT / 'components/pinned_roots/real_roots.c'] if helper else []),
             *libs, '-o', out / name])
    for source, name in [('probe.c', 'fixed'), ('fault_probe.c', 'fault'), ('selection_probe.c', 'selection')]:
        compile_probe(ROOT / 'tools/native_roots' / source, name)
    # Exact SDK bundle implementation, with only ESP platform/logging shims.
    text = (sdk / 'components/mbedtls/esp_crt_bundle/esp_crt_bundle.c').read_text()
    for name in ['esp_check.h', 'esp_crt_bundle.h', 'esp_log.h', 'sdkconfig.h']:
        text = text.replace('#include "' + name + '"', '')
    (out / 'sdk_bundle.c').write_text((ROOT / 'tools/native_roots/bundle_shim.h').read_text() + text)
    compile_probe(ROOT / 'tools/native_roots/baseline.c', 'baseline', helper=False)
    run([sys.executable, sdk / 'components/mbedtls/esp_crt_bundle/gen_crt_bundle.py',
         '--input', ROOT / 'certificates/cacert-2026-10-20.pem'])
    hosts = ['discord.com', 'api.coingecko.com', 'api.coinbase.com', 'mempool.space', 'github.com', 'api.github.com']
    def fixed(name, host, expected, threaded=False):
        certificate = name if isinstance(name, Path) else fixtures / name
        stdout = run([out / 'fixed', certificate, host, '0', '0', str(expected),
                      *(['threads'] if threaded else [])], 0 if threaded else expected)
        if threaded:
            assert 'failed=0' in stdout
        else:
            assert 'residual=0' in stdout
            match = re.search(r'flags=0x([a-f0-9]+)', stdout)
            assert match is not None
            flags_out = int(match[1], 16)
            assert flags_out == (4 if host == 'wrong.example' else 8 if expected else 0)
        rows.append({'name': certificate.name, 'host': host, 'threaded': threaded, 'output': stdout})
    for host in hosts:
        expected = 2 if host in hosts[:3] else 0
        stdout = run([out / 'baseline', out / 'x509_crt_bundle', fixtures / (host + '-full.pem'), host], expected)
        rows.append({'baseline': host, 'output': stdout})
        fixed(host + '-full.pem', host, 0)
        fixed(host + '-full.pem', 'wrong.example', 2)
        if (fixtures / (host + '-short.pem')).exists():
            run([out / 'baseline', out / 'x509_crt_bundle', fixtures / (host + '-short.pem'), host])
            fixed(host + '-short.pem', host, 0)
    incident = sorted(incident_fixtures.glob('*.pem'))
    assert len(incident) == 12
    for f in incident:
        fixed(f, f.stem, 2)
    for name in ['self.pem', 'attacker-full.pem', 'bad-signature.pem']:
        fixed(name, 'api.coingecko.com' if name == 'self.pem' else 'discord.com', 2)
    for host in hosts[:2] + ['mempool.space']:
        fixed(host + '-full.pem', host, 0, True)
        fixed(host + '-full.pem', 'wrong.example', 2, True)
    rows.append({'selection': run([out / 'selection'])})
    # Execute the SDK's complete name comparator on the parsed-name seams.
    sdk_text = (mbed / 'library/x509_crt.c').read_text()
    comparator = []
    for name in ['x509_memcasecmp', 'x509_string_cmp', 'x509_name_cmp']:
        start = sdk_text.index('static int ' + name + '(')
        pos = sdk_text.index('{', start) + 1
        depth = 1
        while depth:
            depth += (sdk_text[pos] == '{') - (sdk_text[pos] == '}')
            pos += 1
        comparator.append(sdk_text[start:pos])
    (out / 'native_comparator.inc').write_text('\n'.join(comparator))
    selection = (ROOT / 'tools/native_roots/selection_probe.c').read_text()
    selection = selection.replace('#include "real_roots.h"', '#include "real_roots.h"\n#include "native_comparator.inc"')
    selection = selection.replace('child.issuer=names[0];',
                                  'child.issuer=names[0];\nif(x509_name_cmp(&child.issuer,&root.subject)!=0)ret=-1;')
    (out / 'native_selection.c').write_text(selection)
    compile_probe(out / 'native_selection.c', 'native-selection', ['-DMBEDTLS_ALLOW_PRIVATE_ACCESS'])
    rows.append({'native_comparator': run([out / 'native-selection'])})
    for name, host, expected in [('discord.com-full.pem', 'discord.com', 0),
                                 ('discord.com-full.pem', 'wrong.example', 2),
                                 ('bad-signature.pem', 'discord.com', 2),
                                 ('mempool.space-full.pem', 'mempool.space', 0)]:
        rows.append({'fault': name, 'host': host,
                     'output': run([out / 'fault', fixtures / name, host, expected])})
    raw = (out / 'roots.inc').read_text()
    helper = (ROOT / 'components/pinned_roots/real_roots.c').read_text()
    variants = {
        'empty': 'static const root_entry roots[1]={{NULL,0,NULL,0}};\n#define ROOT_COUNT 118\n#define ROOT_CANDIDATE_CAP 7\n#define ROOT_DER_CAP 6969\n',
        'corrupt': raw.replace('root_82[] = {48,', 'root_82[] = {0,', 1),
        'truncated': raw.replace('{root_82,sizeof(root_82),', '{root_82,sizeof(root_82)-1,', 1),
        'candidate-cap': raw.replace('#define ROOT_CANDIDATE_CAP 7', '#define ROOT_CANDIDATE_CAP 1'),
        'byte-cap': raw.replace('#define ROOT_DER_CAP 6969', '#define ROOT_DER_CAP 1'),
    }
    for name, data in variants.items():
        (out / (name + '.inc')).write_text(data)
        variant = out / (name + '.c')
        variant.write_text(helper.replace('#include "roots.inc"', '#include "' + name + '.inc"'))
        run([os.environ.get('CC', 'cc'), '-O2', '-pthread', *flags,
             *['-I' + str(p) for p in includes], ROOT / 'tools/native_roots/probe.c',
             variant, *libs, '-o', out / name])
        stdout = run([out / name, fixtures / 'discord.com-full.pem', 'discord.com', '0', '0', '2'], 2)
        assert 'residual=0' in stdout and 'lookup_error=-' in stdout
        rows.append({'variant': name, 'output': stdout})
    compile_probe(ROOT / 'tools/native_roots/mixed_probe.c', 'mixed')
    callback_fault = None
    for index in range(60, 100):
        stdout = run([out / 'fixed', fixtures / 'discord.com-full.pem', 'discord.com', index, '0', '2'], 2)
        if 'lookup_error=-' in stdout and 'residual=0' in stdout:
            callback_fault = index
            break
    assert callback_fault is not None
    rows.append({'mixed_callback_fault': callback_fault,
                 'output': run([out / 'mixed', fixtures / 'discord.com-full.pem', 'discord.com', callback_fault])})
    # A separate validity-enabled build proves the helper does not clear dates.
    time_config = out / 'time_config.h'
    time_config.write_text('#define MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK\n')
    time_flags = [x.replace(str(config), str(time_config)) for x in flags]
    time_cflags = ' '.join(shlex.quote(x) for x in [*['-I' + str(p) for p in includes], *time_flags])
    run(['cmake', '-S', mbed, '-B', out / 'time-build', '-DENABLE_TESTING=OFF',
         '-DENABLE_PROGRAMS=OFF', '-DGEN_FILES=OFF', '-DMBEDTLS_FATAL_WARNINGS=OFF',
         '-DCMAKE_C_FLAGS=' + time_cflags])
    run(['cmake', '--build', out / 'time-build', '--parallel', '8'])
    time_libs = [out / 'time-build/library' / ('lib' + n + '.a') for n in ['mbedtls', 'mbedx509', 'mbedcrypto']]
    run([os.environ.get('CC', 'cc'), '-O2', '-pthread', *time_flags,
         *['-I' + str(p) for p in includes], ROOT / 'tools/native_roots/time_probe.c',
         ROOT / 'components/pinned_roots/real_roots.c', *time_libs, '-o', out / 'time'])
    rows.append({'time_seams': run([out / 'time', fixtures / 'discord.com-full.pem'])})
    (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(f'PASS: {len(rows)} recorded native results; exact SDK baseline failures, fixed positives, negatives, threads, and allocation sweeps')


if __name__ == '__main__':
    main()
