"""Verify an exported ZIP without extracting or executing its contents."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

def verify(path,expected=None):
    result={'package':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'checks':[]}
    if expected: result['anchor_matches']=result['sha256']==expected.lower()
    with zipfile.ZipFile(path) as archive:
        if len(archive.namelist())!=len(set(archive.namelist())): raise ValueError('Duplicate archive member names')
        if sum(x.file_size for x in archive.infolist())>32*1024*1024: raise ValueError('Export exceeds 32 MiB verification limit')
        manifest=json.loads(archive.read('manifest.json'))
        for name,metadata in manifest['files'].items():
            content=archive.read(name)
            result['checks'].append({'file':name,'valid':hashlib.sha256(content).hexdigest()==metadata['sha256'] and len(content)==metadata['bytes']})
        for line in archive.read('SHA256SUMS').decode().splitlines():
            digest,name=line.split('  ',1)
            result['checks'].append({'file':name,'valid':hashlib.sha256(archive.read(name)).hexdigest()==digest})
    result['valid']=bool(result['checks']) and all(x['valid'] for x in result['checks']) and result.get('anchor_matches',True)
    result['scope']='Checksums without a separately retained package hash do not establish independent authenticity.'
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('package',type=Path)
    parser.add_argument('--expected-sha256')
    args=parser.parse_args()
    try: result=verify(args.package,args.expected_sha256)
    except (OSError,ValueError,KeyError,zipfile.BadZipFile) as error: result={'valid':False,'error':str(error)}
    print(json.dumps(result,indent=2))
    sys.exit(0 if result['valid'] else 1)
