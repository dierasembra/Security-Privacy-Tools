#!/usr/bin/env python3
"""security_privacy_tools CLI - defensive helpers to detect and redact sensitive data."""

import click
from pathlib import Path
import re
import sys
import math
from typing import List

# Basic secret regex patterns (non-exhaustive, defensive use only)
SECRET_PATTERNS = {
    'AWS Access Key ID': re.compile(r'AKIA[0-9A-Z]{16}'),
    'AWS Secret Access Key': re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*([A-Za-z0-9/+=]{40})|[A-Za-z0-9/+=]{40}'),
    'Generic API Key': re.compile(r'(?i)(?:api[_-]?key|token)\s*[:=]\s*([A-Za-z0-9\-_.]{16,})'),
    'Private RSA Key': re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    'SSH Private Key': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    'JWT-like': re.compile(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$'),
}

EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+')
IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# small local common password sample
COMMON_PASSWORDS = {'password','123456','qwerty','letmein','admin','welcome'}

def find_in_text(text: str) -> List[tuple]:
    findings = []
    for name, pat in SECRET_PATTERNS.items():
        for m in pat.finditer(text):
            snippet = text[max(0, m.start()-20):m.end()+20].replace('\n',' ')
            findings.append((name, m.group(0), snippet))
    return findings

@click.group()
def cli():
    """Security & Privacy Tools CLI"""
    pass

@cli.command('scan-secrets')
@click.argument('path', type=click.Path(exists=True))
@click.option('--ext', multiple=True, help='Only scan files with these extensions (e.g. .py .env)')
def scan_secrets(path, ext):
    """Scan a file or directory for likely secrets."""
    p = Path(path)
    files = []
    if p.is_file():
        files = [p]
    else:
        for f in p.rglob('*'):
            if f.is_file():
                if ext:
                    if any(str(f).endswith(e) for e in ext):
                        files.append(f)
                else:
                    files.append(f)
    total = 0
    for f in files:
        try:
            text = f.read_text(errors='ignore')
        except Exception as e:
            click.echo(f'Could not read {f}: {e}', err=True); continue
        findings = find_in_text(text)
        if findings:
            click.echo(f'File: {f}')
            for name, match, snippet in findings:
                total += 1
                click.echo(f'  - {name}: {match}\n    ...{snippet}...')
    if total == 0:
        click.echo('No likely secrets found.')
    else:
        click.echo(f'Found {total} possible secret(s). Review manually.')

@cli.command('redact-file')
@click.argument('infile', type=click.Path(exists=True))
@click.argument('outfile', type=click.Path())
@click.option('--mask', default='[REDACTED]', help='Mask to replace secret with')
def redact_file(infile, outfile, mask):
    """Create a redacted copy of a file, masking detected secrets."""
    p_in = Path(infile)
    p_out = Path(outfile)
    text = p_in.read_text(errors='ignore')
    # redact secret patterns
    for name, pat in SECRET_PATTERNS.items():
        text = pat.sub(mask, text)
    # redact emails and IPs by default
    text = EMAIL_RE.sub('[REDACTED_EMAIL]', text)
    text = IPV4_RE.sub('[REDACTED_IP]', text)
    p_out.write_text(text)
    click.echo(f'Wrote redacted file to {p_out}')

@cli.command('sanitize-log')
@click.argument('infile', type=click.Path(exists=True))
@click.argument('outfile', type=click.Path())
@click.option('--keep-ips', is_flag=True, help='Keep IP addresses (do not mask)')
def sanitize_log(infile, outfile, keep_ips):
    """Sanitize a log file by masking emails, IPs, and known secrets."""
    p_in = Path(infile)
    p_out = Path(outfile)
    text = p_in.read_text(errors='ignore')
    text = EMAIL_RE.sub('[REDACTED_EMAIL]', text)
    if not keep_ips:
        text = IPV4_RE.sub('[REDACTED_IP]', text)
    for name, pat in SECRET_PATTERNS.items():
        text = pat.sub('[REDACTED_SECRET]', text)
    p_out.write_text(text)
    click.echo(f'Sanitized log written to {p_out}')

def estimate_entropy(password: str) -> float:
    # Shannon entropy estimate per-character
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^A-Za-z0-9]', password): pool += 32
    if pool == 0: return 0.0
    entropy = len(password) * math.log2(pool)
    return entropy

@cli.command('check-password')
@click.argument('password', required=True)
def check_password(password):
    """Basic password checks: length, entropy estimate, and common-password check."""
    issues = []
    if len(password) < 8:
        issues.append('Password is too short (recommended >= 8 chars)')
    ent = estimate_entropy(password)
    if ent < 50:
        issues.append(f'Estimated entropy low: {ent:.1f} bits (consider longer/stronger password)')
    if password.lower() in COMMON_PASSWORDS:
        issues.append('Password is a common password (do NOT use)')
    if issues:
        click.echo('Password issues:')
        for i in issues:
            click.echo(f' - {i}')
        sys.exit(1)
    click.echo('Password looks reasonably strong (basic checks).')

if __name__ == '__main__':
    cli()
