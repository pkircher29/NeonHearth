"""Refresh offline assignment facts from IEEE's public registries. Maintainer-only;
the app never downloads data or sends network inventory to a lookup service.
"""
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

SOURCES = [('MA-L', 'oui/oui.csv', 6), ('MA-M', 'oui28/mam.csv', 7),
           ('MA-S', 'oui36/oui36.csv', 9), ('IAB', 'iab/iab.csv', 9)]

def main():
    entries, sources, ambiguous = {}, [], set()
    for registry, route, width in SOURCES:
        url = f'https://standards-oui.ieee.org/{route}'
        with urlopen(Request(url, headers={'User-Agent':'NeonHearth-registry-builder/1.0'}), timeout=45) as response:
            data = response.read(12 * 1024 * 1024 + 1)
        if len(data) > 12 * 1024 * 1024:
            raise ValueError('Registry exceeded download limit')
        count = 0
        for row in csv.DictReader(io.StringIO(data.decode('utf-8-sig'))):
            prefix = row['Assignment'].upper()
            organization = ' '.join(row['Organization Name'].split())
            if len(prefix) != width or any(c not in '0123456789ABCDEF' for c in prefix):
                raise ValueError('Invalid IEEE assignment')
            if not organization or len(organization.encode('utf-8')) > 512 or '\t' in organization:
                raise ValueError('Invalid organization')
            value = f'{organization}\t{registry}'
            if prefix in entries and entries[prefix] != value:
                ambiguous.add(prefix)
            if prefix in ambiguous:
                value = f'Ambiguous IEEE assignment\t{registry}'
            entries[prefix] = value
            count += 1
        if count < 1000:
            raise ValueError('Registry is unexpectedly small')
        sources.append({'registry':registry,'url':url,'sha256':hashlib.sha256(data).hexdigest(),'assignments':count})
    folder = Path(__file__).resolve().parents[1] / 'crates/lattice-service/data'
    folder.mkdir(exist_ok=True)
    output = ''.join(f'{key}\t{entries[key]}\n' for key in sorted(entries))
    (folder / 'mac-assignments.tsv').write_text(output, encoding='utf-8', newline='\n')
    manifest = {'source':'IEEE Registration Authority public assignment listings',
                'retrieved_at':datetime.now(timezone.utc).isoformat(), 'sources':sources,
                'assignments':len(entries),'ambiguous_assignments':sorted(ambiguous),'data_sha256':hashlib.sha256(output.encode('utf-8')).hexdigest()}
    (folder / 'mac-assignments.json').write_text(json.dumps(manifest,indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'assignments':len(entries),'bytes':len(output.encode('utf-8'))}))

if __name__ == '__main__':
    main()
