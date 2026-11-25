import os

import pytest

from app.blueprints.utils import ca_utils
from app.blueprints.utils.ca_utils import (
    InvalidNameError, build_sans, cert_path, parse_sans_from_cert_text,
    san_entry, validate_domain, validate_san_entry,
)


@pytest.mark.parametrize('value, expected', [
    ('example.home.local', 'example.home.local'),
    ('  Example.Home.Local  ', 'example.home.local'),
    ('*.home.local', '*.home.local'),
    ('localhost', 'localhost'),
    ('a-b.c1.local', 'a-b.c1.local'),
    ('192.168.1.10', '192.168.1.10'),
    ('::1', '::1'),
])
def test_validate_domain_accepts_hostnames_and_ips(value, expected):
    assert validate_domain(value) == expected


@pytest.mark.parametrize('value', [
    '',
    '   ',
    '../etc/passwd',
    '/app/app/static/k=v',
    './victim.home.local',
    'a\tb.home.local',
    'x.local\nbasicConstraints=CA:TRUE',
    '..\\users\\5\\delete?',
    'junk#',
    'foo bar.local',
    'under_score.local',
    '-leading.local',
    'trailing-.local',
    'double..dot.local',
    'a.*.local',
    '*.*.local',
    'x' * 64 + '.local',
    ('a' * 60 + '.') * 5,
    'rootca',
    'rootCA.home.local',
    'index',
    'serial',
    None,
    123,
])
def test_validate_domain_rejects_unsafe_values(value):
    with pytest.raises(InvalidNameError):
        validate_domain(value)


def test_san_entry_prefixes():
    assert san_entry('host.local') == 'DNS:host.local'
    assert san_entry('10.0.0.1') == 'IP:10.0.0.1'
    with pytest.raises(InvalidNameError):
        san_entry('bad\nname')


@pytest.mark.parametrize('entry', ['DNS:host.local', 'IP:10.0.0.1', 'DNS:*.host.local'])
def test_validate_san_entry_accepts(entry):
    assert validate_san_entry(entry) == entry


@pytest.mark.parametrize('entry', [
    'host.local', 'URI:http://x', 'IP:not-an-ip', 'DNS:bad name',
    'DNS:x\nbasicConstraints=CA:TRUE', 'email:a@b',
])
def test_validate_san_entry_rejects(entry):
    with pytest.raises(InvalidNameError):
        validate_san_entry(entry)


def test_build_sans_dedupes_and_skips_blanks():
    sans = build_sans('host.local', ['', ' host.local ', '10.0.0.1', 'alt.local', 'alt.local'])
    assert sans == ['DNS:host.local', 'IP:10.0.0.1', 'DNS:alt.local']


def test_build_sans_rejects_injection():
    with pytest.raises(InvalidNameError):
        build_sans('host.local', ['ok.local\nkeyUsage=keyCertSign'])


def test_cert_path_stays_inside_ca_dir():
    base = os.path.realpath(ca_utils.CA_DIR)
    assert cert_path('host.local', 'crt') == os.path.join(base, 'host.local.crt')
    for bad in ['../x', '/etc/passwd', 'sub/dir', 'rootCA', 'ROOTCA']:
        with pytest.raises(InvalidNameError):
            cert_path(bad, 'key')


def test_parse_sans_from_cert_text():
    text = (
        'X509v3 extensions:\n'
        '    X509v3 Subject Alternative Name: \n'
        '        DNS:host.local, IP Address:10.0.0.1, DNS:*.host.local\n'
    )
    assert parse_sans_from_cert_text(text) == ['DNS:host.local', 'IP:10.0.0.1', 'DNS:*.host.local']
    assert parse_sans_from_cert_text('') == []
    assert parse_sans_from_cert_text('no sans here') == []
