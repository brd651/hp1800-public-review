# hp1800ctl

`hp1800ctl` is an experimental, unofficial management client for the HP ProCurve
1800-24G (J9028B) running firmware PB.03.10. It is based on observed behavior
of that model and firmware; it is not affiliated with or supported by HPE.

## Support and safety

| Model | Firmware | Status |
| --- | --- | --- |
| HP ProCurve 1800-24G (J9028B) | PB.03.10 | Field-observed; limited testing |

Other models and firmware versions are unverified. Use an isolated management
network with independent recovery access. The switch web interface uses
unencrypted HTTP, so credentials and configuration data can be observed by
other hosts on the network. Use one writer process at a time.

Configuration changes can interrupt management access. Review `plan-config`
output and maintain out-of-band access before applying changes. The tool takes
a pre-change snapshot, but **does not implement automatic rollback**. The
binary configuration upload/restore workflow is unsupported. Factory reset is
destructive, may change the switch address, and its current verification only
confirms management recovery, not that every factory setting or keep-IP value
was restored. Inspect the switch manually after reset.

Snapshots, `switch.cfg`, support reports, and YAML exports can contain SNMP
communities, network details, and other sensitive information. Store them
securely and do not commit or share them without review.

## Install

Python 3.10 or newer is required.

```powershell
python -m pip install .
```

Or run the single-file client after installing its dependencies:

```powershell
python -m pip install requests PyYAML
python hp1800ctl.py --help
```

## Credentials and target

Supply the switch URL explicitly. The default target is `http://192.168.2.10`.
Avoid `--password` because command-line arguments can be visible to other local
processes. Use an interactive prompt or the `HP1800_PASSWORD` environment
variable instead.

```powershell
python -m hp1800ctl --url http://192.168.2.10 --prompt-password status
```

## Common commands

```text
hp1800ctl --url http://192.168.2.10 status
hp1800ctl --url http://192.168.2.10 snapshot -d ./switch-snapshot
hp1800ctl --url http://192.168.2.10 export-config -o desired.yaml
hp1800ctl --url http://192.168.2.10 validate-config desired.yaml
hp1800ctl --url http://192.168.2.10 plan-config desired.yaml
hp1800ctl --url http://192.168.2.10 apply-config desired.yaml
```

`apply-config` is a dry run unless `--apply` is supplied. Read the exported
configuration and planner output before making changes. Management IP changes
and binary restore are not implemented.

## Minimal configuration

Export a configuration from the target first, then edit only the fields you
intend to change. For example:

```yaml
schema: hp1800ctl.config.v1
system:
  name: closet-switch
ports:
  settings:
    1:
      speed_duplex: Auto
      flow_control: false
```

Configuration files are input to a device-management tool. Review them before
use and protect them like switch backups.

## Factory reset

`factory-reset` is destructive and requires `--apply --confirm FACTORY-RESET`.
The `full` mode targets the factory address `192.168.2.10`; `keep-ip` requests
factory defaults while retaining the current address. Do not run either mode
without independent recovery access. A successful login after reboot does not
prove reset completion or preservation of the address, mask, and gateway.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current development notes and
[CHANGELOG.md](CHANGELOG.md) for release history. Report vulnerabilities using
the process in [SECURITY.md](SECURITY.md).
