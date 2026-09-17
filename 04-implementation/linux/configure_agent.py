"""Configure a dedicated Ubuntu lab agent without discarding unrelated settings."""
import argparse
import datetime as dt
import ipaddress
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET


def configure(config: Path, manager: str) -> None:
    ipaddress.IPv4Address(manager)
    document = ET.fromstring('<document>' + config.read_text() + '</document>')
    roots = document.findall('ossec_config')
    if not roots:
        raise ValueError('No ossec_config element in installed configuration')
    first = roots[0]
    for root in roots:
        for node in list(root):
            # Use one auth source. Reading journald as well would duplicate SSH failures.
            if node.tag in ('client', 'active-response') or (
                node.tag == 'localfile' and node.findtext('location') in
                ('journald', '/var/log/auth.log', '/var/log/audit/audit.log')
            ):
                root.remove(node)
    first.append(ET.fromstring(f'''<client><server><address>{manager}</address>
      <port>1514</port><protocol>tcp</protocol></server>
      <enrollment><enabled>no</enabled></enrollment></client>'''))
    for location, format_ in [('/var/log/auth.log', 'syslog'), ('/var/log/audit/audit.log', 'audit')]:
        first.append(ET.fromstring(f'<localfile><location>{location}</location><log_format>{format_}</log_format></localfile>'))
    first.append(ET.fromstring('<active-response><disabled>yes</disabled></active-response>'))
    syscheck = first.find('syscheck')
    if syscheck is None:
        syscheck = ET.SubElement(first, 'syscheck')
    for tag, value in [('disabled', 'no'), ('scan_on_start', 'yes'), ('alert_new_files', 'yes')]:
        for root in roots:
            for existing in root.findall(f'syscheck/{tag}'):
                root.find('syscheck').remove(existing)
        ET.SubElement(syscheck, tag).text = value
    paths = ['/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily',
             '/etc/cron.weekly', '/etc/cron.monthly', '/var/spool/cron/crontabs']
    for root in roots:
        for section in root.findall('syscheck'):
            for node in list(section.findall('directories')):
                remaining = [p.strip() for p in (node.text or '').split(',') if p.strip() not in paths]
                if remaining:
                    node.text = ','.join(remaining)
                else:
                    section.remove(node)
    # /etc/crontab is a file; scheduled scans cover it. Directories get realtime events.
    ET.SubElement(syscheck, 'directories', {'check_all': 'yes', 'report_changes': 'yes'}).text = '/etc/crontab'
    ET.SubElement(syscheck, 'directories', {
        'realtime': 'yes', 'check_all': 'yes', 'report_changes': 'yes'
    }).text = ','.join(paths[1:])
    backup = config.with_name(config.name + '.' + dt.datetime.now().strftime('%Y%m%d%H%M%S%f') + '.bak')
    shutil.copy2(config, backup)
    ET.indent(document, space='  ')
    config.write_text('\n'.join(ET.tostring(root, encoding='unicode') for root in roots) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager', required=True)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=Path('/var/ossec/etc/ossec.conf'))
    args = parser.parse_args()
    key = args.key_file.read_text().strip()
    if not re.fullmatch(r'\d{3,}\s+wazuh-linux\s+\S+\s+[a-fA-F0-9]{64}', key):
        raise SystemExit('Expected the client.keys entry for wazuh-linux')
    configure(args.config, args.manager)
    target = args.config.parent / 'client.keys'
    target.write_text(key + '\n')
    target.chmod(0o640)
