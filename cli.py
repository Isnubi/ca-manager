#!/usr/bin/env python3
"""
CLI equivalent of ca-manager.sh — runs against the same CA directory and database.
Usage: python cli.py [COMMAND] [ARGS]
"""
import os
import sys
import click


def get_app():
    from app import create_app
    return create_app()


@click.group()
def cli():
    """Homelab CA Manager CLI"""


@cli.command()
def init():
    """Initialize the Root CA."""
    app = get_app()
    with app.app_context():
        from app.blueprints.utils import ca_utils
        from app.models import get_setting
        if ca_utils.ca_initialized():
            click.echo('Error: CA is already initialized.', err=True)
            sys.exit(1)
        click.echo('Generating 4096-bit root key (this may take a moment)…')
        try:
            ca_utils.init_ca(
                subj_c=get_setting('CA_COUNTRY'),
                subj_st=get_setting('CA_STATE'),
                subj_l=get_setting('CA_LOCALITY'),
                subj_o=get_setting('CA_ORG'),
                days_valid_root=int(get_setting('DAYS_VALID_ROOT')),
            )
            click.secho('Root CA initialized successfully.', fg='green')
            click.echo(f"  CA cert: {ca_utils.CA_CERT}")
            click.echo("  Install the CA cert in your trusted root store.")
        except Exception as e:
            click.echo(f'Error: {e}', err=True)
            sys.exit(1)


@cli.command()
@click.argument('domain')
@click.option('--san', multiple=True, help='Additional SAN (can be repeated)')
def issue(domain, san):
    """Issue a certificate for DOMAIN."""
    app = get_app()
    with app.app_context():
        from datetime import datetime, timedelta
        from app.blueprints.utils import ca_utils
        from app import db
        from app.models import Certificate, get_setting

        if not ca_utils.ca_initialized():
            click.echo('Error: CA is not initialized. Run: python cli.py init', err=True)
            sys.exit(1)

        if Certificate.query.filter_by(domain=domain, status='valid').first():
            click.echo(f'Error: A valid certificate for {domain} already exists.', err=True)
            sys.exit(1)

        sans = [f'DNS:{domain}'] + [f'DNS:{s}' for s in san if f'DNS:{s}' != f'DNS:{domain}']
        days = int(get_setting('DAYS_VALID_CERT'))

        click.echo(f'Issuing certificate for {domain}…')
        try:
            serial = ca_utils.issue_cert(
                domain=domain, sans=sans,
                subj_c=get_setting('CA_COUNTRY'),
                subj_st=get_setting('CA_STATE'),
                subj_l=get_setting('CA_LOCALITY'),
                subj_o=get_setting('CA_ORG'),
                subj_ou=get_setting('CA_OU'),
                days_valid_cert=days,
            )
            cert = Certificate(
                domain=domain, serial=serial, status='valid',
                issued_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(days=days),
            )
            db.session.add(cert)
            db.session.commit()
            click.secho(f'Certificate issued for {domain}.', fg='green')
            click.echo(f"  Cert: {os.path.join(ca_utils.CA_DIR, domain + '.crt')}")
            click.echo(f"  Key:  {os.path.join(ca_utils.CA_DIR, domain + '.key')}")
        except Exception as e:
            click.echo(f'Error: {e}', err=True)
            sys.exit(1)


@cli.command(name='list')
def list_certs():
    """List all certificates."""
    app = get_app()
    with app.app_context():
        from app.models import Certificate
        certs = Certificate.query.order_by(Certificate.issued_at.desc()).all()
        if not certs:
            click.echo('No certificates found.')
            return
        click.echo(f"{'Domain':<35} {'Serial':<20} {'Status':<10} {'Expires'}")
        click.echo('-' * 80)
        for c in certs:
            expires = c.expires_at.strftime('%Y-%m-%d') if c.expires_at else 'N/A'
            status = click.style('REVOKED', fg='red') if c.status == 'revoked' else click.style('valid', fg='green')
            click.echo(f"{c.domain:<35} {c.serial[:18]:<20} {status:<10} {expires}")


@cli.command()
@click.argument('domain')
def show(domain):
    """Show certificate PEM content for DOMAIN."""
    app = get_app()
    with app.app_context():
        from app.blueprints.utils import ca_utils
        crt_path = os.path.join(ca_utils.CA_DIR, f'{domain}.crt')
        key_path = os.path.join(ca_utils.CA_DIR, f'{domain}.key')
        if not os.path.exists(crt_path):
            click.echo(f'Error: Certificate for {domain} not found.', err=True)
            sys.exit(1)
        click.echo(f'\n--- CERTIFICATE ({domain}.crt) ---')
        click.echo(open(crt_path).read())
        if os.path.exists(key_path):
            click.echo(f'--- PRIVATE KEY ({domain}.key) ---')
            click.echo(open(key_path).read())


@cli.command()
@click.argument('domain')
def revoke(domain):
    """Revoke the certificate for DOMAIN."""
    app = get_app()
    with app.app_context():
        from datetime import datetime
        from app.blueprints.utils import ca_utils
        from app import db
        from app.models import Certificate
        cert = Certificate.query.filter_by(domain=domain, status='valid').first()
        if not cert:
            click.echo(f'Error: No valid certificate found for {domain}.', err=True)
            sys.exit(1)
        click.confirm(f'Revoke certificate for {domain}?', abort=True)
        cert.status = 'revoked'
        cert.revoked_at = datetime.utcnow()
        db.session.commit()
        ca_utils.regen_crl(Certificate.query.all())
        click.secho(f'Certificate for {domain} revoked.', fg='yellow')


@cli.command('show-ca')
def show_ca():
    """Show the Root CA certificate."""
    app = get_app()
    with app.app_context():
        from app.blueprints.utils import ca_utils
        if not ca_utils.ca_initialized():
            click.echo('Error: CA not initialized.', err=True)
            sys.exit(1)
        click.echo(open(ca_utils.CA_CERT).read())


if __name__ == '__main__':
    cli()
