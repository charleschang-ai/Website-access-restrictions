"""Country lookup based on the APNIC delegation statistics, without third-party dependencies."""
import bisect
import ipaddress
from collections import Counter

APNIC_URL = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'


def compact_apnic(text):
    """Keep only the IP allocations of an APNIC delegated file, as 'CC|ipv4|start|value' lines.

    The first line records the date of the source file as '#date=YYYYMMDD'.
    """
    date, lines = '', []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if parts[0] == '2' and len(parts) > 2:
            date = parts[2]
        elif (len(parts) >= 7 and len(parts[1]) == 2 and parts[2] in ('ipv4', 'ipv6')
                and parts[6] in ('allocated', 'assigned')):
            lines.append('|'.join(parts[1:5]))
    return '\n'.join([f'#date={date}', *lines]) + '\n'


class IpTable:
    """Sorted, merged IP ranges per country, searched by bisection."""

    def __init__(self, compact_text):
        self.date = ''
        self.counts = Counter()
        rows = {4: [], 6: []}
        for line in compact_text.splitlines():
            if line.startswith('#date='):
                self.date = line[6:]
                continue
            parts = line.strip().split('|')
            if len(parts) != 4 or parts[1] not in ('ipv4', 'ipv6'):
                continue
            cc, kind, start, value = parts
            try:
                start_int, value = int(ipaddress.ip_address(start)), int(value)
            except ValueError:
                continue
            if kind == 'ipv4':
                rows[4].append((start_int, start_int + value - 1, cc))
            else:
                rows[6].append((start_int, start_int + (1 << (128 - value)) - 1, cc))
            self.counts[cc, kind] += 1

        self._tables = {}
        for version, ranges in rows.items():
            ranges.sort()
            merged = []
            for start, end, cc in ranges:
                if merged and merged[-1][2] == cc and merged[-1][1] + 1 >= start:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end, cc])
            self._tables[version] = (
                [r[0] for r in merged], [r[1] for r in merged], [r[2] for r in merged],
            )

    def __len__(self):
        return sum(self.counts.values())

    def country(self, ip):
        """Country code of an ``ipaddress`` address, or None when it is not an APNIC allocation."""
        starts, ends, ccs = self._tables[ip.version]
        value = int(ip)
        i = bisect.bisect_right(starts, value) - 1
        if i >= 0 and value <= ends[i]:
            return ccs[i]
        return None
