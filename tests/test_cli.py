import pytest
from click.testing import CliRunner

import cli as cli_module
from app.models import Certificate


@pytest.fixture
def runner(app, monkeypatch):
    monkeypatch.setattr(cli_module, 'get_app', lambda: app)
    return CliRunner()


def test_issue_list_show_revoke(app, ca, runner):
    r = runner.invoke(cli_module.cli, ['issue', 'cli.home.local', '--san', 'alt.home.local'])
    assert r.exit_code == 0, r.output
    with app.app_context():
        cert = Certificate.query.one()
        assert cert.sans == 'DNS:cli.home.local,DNS:alt.home.local'

    r = runner.invoke(cli_module.cli, ['list'])
    assert 'cli.home.local' in r.output

    r = runner.invoke(cli_module.cli, ['show', 'cli.home.local'])
    assert 'BEGIN CERTIFICATE' in r.output

    r = runner.invoke(cli_module.cli, ['revoke', 'cli.home.local'], input='y\n')
    assert r.exit_code == 0, r.output
    with app.app_context():
        assert Certificate.query.one().status == 'revoked'


def test_issue_rejects_bad_domain(app, ca, runner):
    r = runner.invoke(cli_module.cli, ['issue', '../escape'])
    assert r.exit_code == 1 and 'Invalid domain' in r.output


def test_issue_rejects_existing_domain(app, ca, runner):
    runner.invoke(cli_module.cli, ['issue', 'dup.home.local'])
    r = runner.invoke(cli_module.cli, ['issue', 'dup.home.local'])
    assert r.exit_code == 1 and 'already exists' in r.output


def test_commands_require_ca(runner):
    assert runner.invoke(cli_module.cli, ['issue', 'x.local']).exit_code == 1
    assert runner.invoke(cli_module.cli, ['show-ca']).exit_code == 1
    assert 'No certificates' in runner.invoke(cli_module.cli, ['list']).output


def test_show_ca(ca, runner):
    r = runner.invoke(cli_module.cli, ['show-ca'])
    assert r.exit_code == 0 and 'BEGIN CERTIFICATE' in r.output
