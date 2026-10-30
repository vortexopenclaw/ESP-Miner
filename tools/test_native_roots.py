#!/usr/bin/env python3
"""Offline stock/cross-sign SDK bundle regression; never a device or socket."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
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
    fixtures = ROOT / 'tools/native_roots/fixtures'
    manifest = json.loads((fixtures / 'sha256.json').read_text())
    expected_names = {'braiins.com-full.pem', 'braiins.com-short.pem', 'public-pool.io-full.pem',
                      'attacker-full.pem', 'bad-signature.pem', 'self.pem'}
    if set(manifest) != expected_names or {f.name for f in fixtures.glob('*.pem')} != expected_names:
        raise RuntimeError('Expected exactly the six documented certificate fixtures')
    for name, digest in manifest.items():
        if hashlib.sha256((fixtures / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f'Fixture checksum mismatch: {name}')
    bundle = ROOT / 'certificates/cacert-2026-10-20.pem'
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != bundle.with_suffix('.pem.sha256').read_text().split()[0]:
        raise RuntimeError('Pinned CA checksum mismatch')
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
    config = out / 'native_config.h'
    # Match firmware's inherited time policy; archived incident leaves can expire.
    config.write_text('#undef MBEDTLS_HAVE_TIME_DATE\n#define MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK\n')
    compat = out / 'compat/mbedtls'
    compat.mkdir(parents=True)
    for header in (mbed / 'tf-psa-crypto/drivers/builtin/include/mbedtls/private').glob('*.h'):
        (compat / header.name).write_text('#include "' + str(header) + '"\n')
    includes = [mbed / 'include', mbed / 'tf-psa-crypto/include',
                mbed / 'tf-psa-crypto/drivers/builtin/include', compat.parent,
                ROOT / 'tools/native_roots', out]
    flags = ['-DMBEDTLS_THREADING_C', '-DMBEDTLS_THREADING_PTHREAD',
             '-DMBEDTLS_PLATFORM_MEMORY', '-DMBEDTLS_USER_CONFIG_FILE="' + str(config) + '"']
    cflags = ' '.join(shlex.quote(x) for x in [*['-I' + str(p) for p in includes], *flags])
    run(['cmake', '-S', mbed, '-B', out / 'build', '-DENABLE_TESTING=OFF',
         '-DENABLE_PROGRAMS=OFF', '-DGEN_FILES=OFF', '-DMBEDTLS_FATAL_WARNINGS=OFF',
         '-DCMAKE_C_FLAGS=' + cflags])
    run(['cmake', '--build', out / 'build', '--parallel', '8'])
    libs = [out / 'build/library' / ('lib' + n + '.a') for n in ['mbedtls', 'mbedx509', 'mbedcrypto']]
    text = (sdk / 'components/mbedtls/esp_crt_bundle/esp_crt_bundle.c').read_text()
    for name in ['esp_check.h', 'esp_crt_bundle.h', 'esp_log.h', 'sdkconfig.h']:
        text = text.replace('#include "' + name + '"', '')
    (out / 'sdk_bundle.c').write_text((ROOT / 'tools/native_roots/bundle_shim.h').read_text() + text)
    for mode in ['stock', 'cross-sign']:
        run([os.environ.get('CC', 'cc'), '-O2', '-pthread', *flags,
             *['-I' + str(p) for p in includes], '-I' + str(mbed / 'library'),
             *(['-DCONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY=1'] if mode == 'cross-sign' else []),
             ROOT / 'tools/native_roots/baseline.c', *libs, '-o', out / mode])
    run([sys.executable, sdk / 'components/mbedtls/esp_crt_bundle/gen_crt_bundle.py', '--input', bundle])
    cases = [
        (fixtures / 'braiins.com-full.pem', 'braiins.com', 2, 0),
        (fixtures / 'braiins.com-short.pem', 'braiins.com', 0, 0),
        (fixtures / 'public-pool.io-full.pem', 'public-pool.io', 0, 0),
        (fixtures / 'braiins.com-short.pem', 'wrong.example', 2, 2),
        (fixtures / 'braiins.com-full.pem', 'wrong.example', 2, 2),
        (fixtures / 'public-pool.io-full.pem', 'wrong.example', 2, 2),
        *[(fixtures / name, 'braiins.com', 2, 2)
          for name in ['attacker-full.pem', 'bad-signature.pem', 'self.pem']],
        *[(f, f.stem, 2, 2) for f in sorted(incident_fixtures.glob('*.pem'))],
    ]
    assert len(cases) == 21
    for mode, index in [('stock', 2), ('cross-sign', 3)]:
        for case in cases:
            certificate, host = case[:2]
            expected = case[index]
            stdout = run([out / mode, out / 'x509_crt_bundle', certificate, host], expected)
            match = re.search(r'flags=0x([a-f0-9]+)\s*$', stdout)
            assert match is not None
            flags_out = int(match[1], 16)
            assert flags_out != 0 if expected else flags_out == 0
            if host == 'wrong.example' and (mode == 'cross-sign' or certificate.name != 'braiins.com-full.pem'):
                assert flags_out & 4  # CN_MISMATCH, not merely missing trust.
            rows.append({'mode': mode, 'name': certificate.name, 'host': host,
                         'expected_exit': expected, 'output': stdout})
    (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(f'PASS: {len(rows)} SDK bundle results: stock/cross-sign positives, wrong hosts, impostor, bad signature, self-signed, all 12 incident chains')


if __name__ == '__main__':
    main()
