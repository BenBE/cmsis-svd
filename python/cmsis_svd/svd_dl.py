#!/usr/bin/env python
#
# Copyright 2015-2024 cmsis-svd Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import gzip
import hashlib
import json
import os
import random
import re
import shutil
import socket
import tarfile
import time

from typing import Dict, Optional, Union
from urllib import request
from urllib.error import HTTPError

# Check for pyzstd for ZStandard compression support
try:
    have_zstd = True
    import pyzstd

    zstd_options = {
        pyzstd.CParameter.compressionLevel : 10,
        pyzstd.CParameter.checksumFlag : 1,
        pyzstd.CParameter.nbWorkers : 4,
    }
except ImportError:
    have_zstd = False

original_print = print
def print(*args, **kwargs):
    kwargs.setdefault('flush', True)
    original_print(*args, **kwargs)


INDEX_JSON = 'index.json'
INDEX_JSON_GZIP = INDEX_JSON + '.gz'
INDEX_JSON_ZSTD = INDEX_JSON + '.zstd'
INDEX_HASH = 'index.hash'

CMSIS_SVD_DATA_URL = ('https://raw.githubusercontent.com'
                      '/cmsis-svd/cmsis-svd-data/refs/heads/svd-indexer')

LOCAL_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
LOCAL_DATA_INDEX_JSON = os.path.join(LOCAL_DATA_DIR, INDEX_JSON)
LOCAL_DATA_INDEX_JSON_GZIP = os.path.join(LOCAL_DATA_DIR, INDEX_JSON_GZIP)
LOCAL_DATA_INDEX_JSON_ZSTD = os.path.join(LOCAL_DATA_DIR, INDEX_JSON_ZSTD)
LOCAL_DATA_INDEX_HASH = os.path.join(LOCAL_DATA_DIR, INDEX_HASH)


class SvdDlError(Exception):
    pass


class SvdDl:

    _svd_resource_matcher = re.compile(
        r'^([a-zA-Z0-9_-]+)(\.([a-zA-Z0-9_-]+)){0,3}$')
    _svd_hash_matcher = re.compile(
        r'^[a-z0-9_-]{128}$')

    def __init__(self, repo=CMSIS_SVD_DATA_URL, datadir=LOCAL_DATA_DIR):
        socket.setdefaulttimeout(2)
        self.repo = repo
        self.datadir = datadir
        self.index_json = {}

    def _repourl(self, path: str) -> str:
        return f'{self.repo}/{path}'

    def _datapath(self, path: str) -> str:
        return os.path.join(self.datadir, path)

    @staticmethod
    def _get_file_hash(filename: Union[str, os.PathLike]) -> str:
        with open(filename, 'rb') as f:
            return hashlib.sha512(f.read()).hexdigest()

    @staticmethod
    def _get_hash_from_index_hash(filename: Union[str, os.PathLike], target: str = INDEX_JSON) -> str:
        with open(filename, 'r') as f:
            content = map(lambda s: s.strip(), f.readlines())

        content = [l.split(' ') for l in content]

        for h in content:
            hf = ' '.join(h[:-1])
            hv = ' '.join(h[-1:])

            if hf != target:
                continue

            if not SvdDl._svd_hash_matcher.match(hv):
                raise SvdDlError('Invalid hash entry in index.hash file.')

            return hv

        raise SvdDlError('Entry not found in index.hash file.')

    def _validate_index(self) -> bool:
        for k in ['files', 'packages', 'source']:
            if k not in self.index_json:
                return False

        for f in self.index_json['files']:
            if not SvdDl._svd_resource_matcher.match(f):
                return False
            fv = self.index_json['files'][f]
            for k in ['hash', 'paths', 'size']:
                if k not in fv:
                    return False
            if not SvdDl._svd_hash_matcher.match(fv['hash']):
                return False
            for k in ['plain', 'gzip']:
                if k not in fv['paths']:
                    return False

        for p in self.index_json['packages']:
            if not SvdDl._svd_resource_matcher.match(p):
                return False
            pv = self.index_json['packages'][p]
            if 'contents' not in pv:
                return False
            if 'files' not in pv:
                return False
            pvf = pv['files']
            if 'gzip' not in pvf:
                return False
            for k in ['hash', 'name', 'size']:
                if k not in pvf['gzip']:
                    return False
            if not SvdDl._svd_hash_matcher.match(pvf['gzip']['hash']):
                return False
            if 'zstd' in pvf:
                for k in ['hash', 'name', 'size']:
                    if k not in pvf['zstd']:
                        return False
                if not SvdDl._svd_hash_matcher.match(pvf['zstd']['hash']):
                    return False
            pc = pv['contents']
            for pcf in pc:
                if pcf not in self.index_json['files'].keys():
                    return False

        return True

    @staticmethod
    def _urlretrieve_wrapper(url: str, filename: Union[str, os.PathLike], retry: int = 5) -> None:
        retry_count = 1
        delay = [2, 5]

        while True:
            try:
                with request.urlopen(url) as response:
                    if response.status == 200:
                        with open(filename, 'wb') as out_file:
                            out_file.write(response.read())
                        return
                    elif response.status == 428:
                        delay = list(map(lambda x: x * 2, delay))
                    elif 400 <= response.status < 500 or retry_count >= retry:
                        raise HTTPError(url, response.status, response.reason, response.headers, None)
            except Exception as e:
                if retry_count >= retry:
                    raise e

            retry_count += 1
            time.sleep(random.randrange(*delay))

    @staticmethod
    def _decompress_file_gz(compressed: str, target: str) -> None:
        with gzip.open(compressed, 'rb') as f_in:
            with open(target, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    @staticmethod
    def _decompress_file_zstd(compressed: str, target: str) -> None:
        with ZstdFile(compressed, 'rb') as f_in:
            with open(target, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    def _decompress_archive_extract_filter(self, entry: tarfile.TarInfo, targets: Dict[str, str]) -> Optional[tarfile.TarInfo]:
        if not entry.isreg():
            return None

        if entry.name not in targets.values():
            return None

        entry = tarfile.data_filter(entry, self.datadir)

        sanitized = tarfile.TarInfo(name=entry.name)
        sanitized.size = entry.size
        return sanitized

    def _decompress_archive_gz(self, compressed: str, path: str, targets: Dict[str, str]) -> None:
        with tarfile.open(compressed, mode='r:gz') as tar:
            tar.extractall(path=path, filter=lambda m, p: self._decompress_archive_extract_filter(m, targets))

    def _decompress_archive_zstd(self, compressed: str, path: str, targets: Dict[str, str]) -> None:
        with pyzstd.ZstdFile(compressed, 'rb') as f_in:
            with tarfile.open(fileobj=f_in, mode='r:') as tar:
                tar.extractall(path=path, filter=lambda m, p: self._decompress_archive_extract_filter(m, targets))

    def dl_svd_to_local(self, dotted_name: str):
        if dotted_name not in self.index_json['files']:
            raise SvdDlError(f'SVD resource {dotted_name} could not be found in the index')

        svd_info = self.index_json['files'][dotted_name]
        svd_hash = svd_info['hash']

        svd_path_part = dotted_name.replace('.', os.sep) + '.svd'
        svd_path = self._datapath(svd_path_part)
        svd_path_gzip = self._datapath(svd_path_part + '.gz')
        svd_path_zstd = self._datapath(svd_path_part + '.zstd')

        if os.path.exists(svd_path):
            if not os.path.isfile(svd_path):
                raise SvdDlError(f'SVD resource {dotted_name} at {svd_path} exists, but is not a regular file')

            if self._get_file_hash(svd_path) == svd_hash:
                print(f'[+] SVD already exists: "{dotted_name}"')
                return
            else:
                print(f'[i] SVD already exists, but hash differs: "{dotted_name}" (updating)')

        os.makedirs(os.path.dirname(svd_path), exist_ok=True)

        print(f'[i] Downloading: "{dotted_name}"')
        svd_url_plain = self._repourl(svd_info["paths"]["plain"])
        svd_url_gzip = self._repourl(svd_info["paths"]["gzip"])
        svd_url_zstd = self._repourl(svd_info["paths"]["zstd"])

        have_file = False
        if have_zstd:
            try:
                self._urlretrieve_wrapper(svd_url_zstd, svd_path_zstd)
                try:
                    self._decompress_file_zstd(svd_path_zstd, svd_path)
                finally:
                    os.unlink(svd_path_zstd)
                have_file = True
            except:
                have_file = False

        if not have_file:
            try:
                self._urlretrieve_wrapper(svd_url_gzip, svd_path_gzip)
                try:
                    self._decompress_file_gz(svd_path_gzip, svd_path)
                finally:
                    os.unlink(svd_path_gzip)
                have_file = True
            except:
                have_file = False

        if not have_file:
            self._urlretrieve_wrapper(svd_url_plain, svd_path)

        if self._get_file_hash(svd_path) != svd_hash:
            raise SvdDlError(f'Downloaded SVD file for "{dotted_name}" is corrupted.')

    def dl_pack_to_local(self, dotted_name: str):
        if dotted_name not in self.index_json['packages']:
            raise SvdDlError(f'SVD resource pack {dotted_name} could not be found in the index')

        pack_info = self.index_json['packages'][dotted_name]

        # Check for existing files
        print(f'[i] Checking existing files for pack: {dotted_name}')
        extract_files = pack_info['contents']

        correct_files = []
        for k, v in extract_files.items():
            if k not in self.index_json['files']:
                raise SvdDlError(f'No information available about archived SVD resource {k} in pack {dotted_name}')

            file_info = self.index_json['files'][k]

            ef = os.path.join(LOCAL_DATA_DIR, v)
            if os.path.exists(ef):
                file_hash = self._get_file_hash(ef)
                if file_hash == file_info['hash']:
                    print(f'[+] SVD resource {k} in pack {dotted_name} already up-to-date')
                    correct_files.append(k)

        extract_files = {k: v for k, v in extract_files.items() if k not in correct_files}

        if len(extract_files) == 0:
            print(f'[+] Nothing left to update for pack: {dotted_name}')
            return

        have_archive = False

        # Download pack via zstd if available
        if 'zstd' in pack_info['files'] and have_zstd:
            pack_relname = pack_info["files"]["zstd"]["name"]
            pack_url_zstd = self._repourl(pack_relname)
            pack_path_zstd = self._datapath(pack_relname)
            try:
                print(f'[i] Downloading pack "{dotted_name}" from "{pack_url_zstd}"')
                self._urlretrieve_wrapper(pack_url_zstd, pack_path_zstd)

                #   Extract pack from .tar.zstd
                try:
                    self._decompress_archive_zstd(pack_path_zstd, LOCAL_DATA_DIR, extract_files)
                finally:
                    os.unlink(pack_path_zstd)

                have_archive = True
            except:
                have_archive = False

        # Download pack via gzip if available
        if 'gzip' in pack_info['files'] and not have_archive:
            pack_relname = pack_info["files"]["gzip"]["name"]
            pack_url_gzip = self._repourl(pack_relname)
            pack_path_gzip = self._datapath(pack_relname)
            try:
                print(f'[i] Downloading pack "{dotted_name}" from "{pack_url_gzip}"')
                self._urlretrieve_wrapper(pack_url_gzip, pack_path_gzip)

                #   Extract pack from .tar.gz
                try:
                    self._decompress_archive_gz(pack_path_gzip, LOCAL_DATA_DIR, extract_files)
                finally:
                    os.unlink(pack_path_gzip)

                have_archive = True
            except:
                have_archive = False

        if not have_archive:
            raise SvdDlError(f'Failed to download SVD resource pack for "{dotted_name}".')

        # Verify extracted files

        pass

    def download_svd(self, download_string: str) -> None:
        download_files, download_packs = [], []
        os.makedirs(LOCAL_DATA_DIR, exist_ok=True)

        print(f'[i] Downloading: index.hash')

        self._urlretrieve_wrapper(self._repourl(INDEX_HASH), LOCAL_DATA_INDEX_HASH)

        print(f'[i] Downloading: index.json')

        have_index = False

        if os.path.exists(LOCAL_DATA_INDEX_JSON):
            if self._get_hash_from_index_hash(LOCAL_DATA_INDEX_HASH, 'index.json') == self._get_file_hash(LOCAL_DATA_INDEX_JSON):
                have_index = True

        if not have_index and have_zstd:
            try:
                self._urlretrieve_wrapper(self._repourl(INDEX_JSON_ZSTD), LOCAL_DATA_INDEX_JSON_ZSTD)
                index_json_hash = self._get_file_hash(LOCAL_DATA_INDEX_JSON_ZSTD)
                index_json_hash_valid = self._get_hash_from_index_hash(LOCAL_DATA_INDEX_HASH, target=INDEX_JSON_ZSTD)
                if index_json_hash != index_json_hash_valid:
                    raise SvdDlError(f'"{INDEX_JSON_ZSTD}" is corrupted.')

                try:
                    self._decompress_file_zstd(LOCAL_DATA_INDEX_JSON_ZSTD, LOCAL_DATA_INDEX_JSON)
                finally:
                    os.unlink(LOCAL_DATA_INDEX_JSON_ZSTD)

                have_index = True
            except:
                have_index = False

        if not have_index:
            try:
                self._urlretrieve_wrapper(self._repourl(INDEX_JSON_GZIP), LOCAL_DATA_INDEX_JSON_GZIP)
                index_json_hash = self._get_file_hash(LOCAL_DATA_INDEX_JSON_GZIP)
                index_json_hash_valid = self._get_hash_from_index_hash(LOCAL_DATA_INDEX_HASH, target=INDEX_JSON_GZIP)
                if index_json_hash != index_json_hash_valid:
                    raise SvdDlError(f'"{INDEX_JSON_GZIP}" is corrupted.')

                try:
                    self._decompress_file_gz(LOCAL_DATA_INDEX_JSON_GZIP, LOCAL_DATA_INDEX_JSON)
                finally:
                    os.unlink(LOCAL_DATA_INDEX_JSON_GZIP)

                have_index = True
            except:
                have_index = False

        if not have_index:
            request.urlretrieve(self._repourl(INDEX_JSON), LOCAL_DATA_INDEX_JSON)

        # Check decompressed index.json
        print(f'[i] Validating: {INDEX_JSON}')
        index_json_hash = self._get_file_hash(LOCAL_DATA_INDEX_JSON)
        index_json_hash_valid = self._get_hash_from_index_hash(LOCAL_DATA_INDEX_HASH)
        if index_json_hash != index_json_hash_valid:
            raise SvdDlError(f'"{INDEX_JSON}" is corrupted.')

        with open(LOCAL_DATA_INDEX_JSON, 'r') as f:
            self.index_json = json.load(f)

        if not self._validate_index():
            raise SvdDlError(f'"{INDEX_JSON}" contains invalid data.')

        if download_string == 'ALL':
            download_packs = self.index_json['packages'].keys()
            download_files = self.index_json['files'].keys()
        else:
            svd_resources = download_string.split(',')
            pkg_names = self.index_json['packages'].keys()
            file_names = self.index_json['files'].keys()
            for res in svd_resources:
                if SvdDl._svd_resource_matcher.match(res) is None:
                    raise SvdDlError(f'Invalid pattern for SVD resource "{res}"')

                if res in pkg_names:
                    download_packs.append(res)
                elif res in file_names:
                    download_files.append(res)
                else:
                    raise SvdDlError(f'There is no package or SVD resource called "{res}"')

        # Remove files also imported via some package
        files_to_remove = set()
        for pkgname in download_packs:
            if pkgname in self.index_json['packages'].keys():
                files_to_remove.update(self.index_json['packages'][pkgname]['contents'])
        download_files = [f for f in download_files if f not in files_to_remove]

        for pkg in sorted(list(set(download_packs))):
            print(f'[i] Processing pack: {pkg}')
            self.dl_pack_to_local(pkg)

        for file in sorted(list(set(download_files))):
            print(f'[i] Processing file: {file}')
            self.dl_svd_to_local(file)


def main():
    parser = argparse.ArgumentParser(
        prog='svd-dl',
        description=f'SVD file downloader from the cmsis-svd project.'
    )

    subparsers = parser.add_subparsers(required=True, dest='svd_dl_subparser')
    sub_parser_dl = 'download'
    parser_dl = subparsers.add_parser(sub_parser_dl, help='download SVD file')
    parser_dl.add_argument(
        '--svd-resources', required=True,
        help='List of svd resources with doted notation. '
             'ex: Atmel.AT91SAM9CN11,Nordic')
    parser_dl.add_argument(
        '--svd-repo', default=CMSIS_SVD_DATA_URL,
        help='URL for where the SVD resource repository can be found')

    script_args = parser.parse_args()

    if script_args.svd_dl_subparser == sub_parser_dl:
        SvdDl(repo=script_args.svd_repo).download_svd(script_args.svd_resources)

if __name__ == '__main__':
    main()
