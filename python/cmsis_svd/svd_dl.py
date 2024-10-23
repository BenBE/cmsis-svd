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

from abc import ABC, abstractmethod
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
INDEX_HASH = 'index.hash'

CMSIS_SVD_DATA_URL = ('https://raw.githubusercontent.com'
                      '/cmsis-svd/cmsis-svd-data/refs/heads/svd-indexer')

LOCAL_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


class SvdDlError(Exception):
    pass


class SvdDlFormat(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    def prio(self) -> int:
        return 0

    @property
    def available(self) -> bool:
        return False

    @property
    @abstractmethod
    def fileext(self) -> str:
        pass

    @staticmethod
    @abstractmethod
    def _decompress_file(compressed: str, target: str) -> None:
        pass

    @staticmethod
    @abstractmethod
    def _decompress_archive(compressed: str, path: str, targets: Dict[str, str]) -> None:
        pass

    def _add_fileext(filename: str) -> str:
        return filename + self.fileext

    @staticmethod
    def _gen_extract_filter(datadir: str, targets: Dict[str, str]) -> callable:
        def impl(entry: tarfile.TarInfo, extractpath: str) -> Optional[tarfile.TarInfo]:
            if not entry.isreg():
                return None

            if entry.name not in targets.values():
                return None

            if hasattr(tarfile, 'data_filter'):
                entry = tarfile.data_filter(entry, datadir)
            else:
                # Re-implement a sane subset
                dest_path = os.path.realpath(datadir)
                # Ensure we stay in the destination
                target_path = os.path.realpath(os.path.join(dest_path, entry.name))
                if os.path.commonpath([target_path, dest_path]) != dest_path:
                    raise OutsideDestinationError(member, target_path)

            sanitized = tarfile.TarInfo(name=entry.name)
            sanitized.size = entry.size
            return sanitized
        return impl


class SvdDlFormatPlain(SvdDlFormat):
    @property
    def id(self) -> str:
        return "plain"

    @property
    def available(self) -> bool:
        return True

    @property
    def fileext(self) -> str:
        return ''

    @staticmethod
    @abstractmethod
    def _decompress_file(compressed: str, target: str) -> None:
        if compressed == target:
            return

        shutil.copyfile(compressed, target)

    @staticmethod
    @abstractmethod
    def _decompress_archive(compressed: str, path: str, targets: Dict[str, str]) -> None:
        raise NotImplementedError(f'Uncompressed archives are not implemented')


class SvdDlFormatGzip(SvdDlFormat):
    @property
    def id(self) -> str:
        return "gzip"

    @property
    def prio(self) -> int:
        return 1

    @property
    def available(self) -> bool:
        return True

    @property
    def fileext(self) -> str:
        return '.gz'

    @staticmethod
    def _decompress_file(compressed: str, target: str) -> None:
        with gzip.open(compressed, 'rb') as f_in:
            with open(target, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    @staticmethod
    def _decompress_archive(compressed: str, path: str, targets: Dict[str, str]) -> None:
        with tarfile.open(compressed, mode='r:gz') as tar:
            tar.extraction_filter = SvdDlFormat._gen_extract_filter(datadir=path, targets=targets)
            tar.extractall(path=path)


class SvdDlFormatZstd(SvdDlFormat):
    @property
    def id(self) -> str:
        return "zstd"

    @property
    def prio(self) -> int:
        return 2

    @property
    def available(self) -> bool:
        return have_zstd

    @property
    def fileext(self) -> str:
        return '.zstd'

    @staticmethod
    def _decompress_file(compressed: str, target: str) -> None:
        with ZstdFile(compressed, 'rb') as f_in:
            with open(target, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    @staticmethod
    def _decompress_archive(compressed: str, path: str, targets: Dict[str, str]) -> None:
        with pyzstd.ZstdFile(compressed, 'rb') as f_in:
            with tarfile.open(fileobj=f_in, mode='r:') as tar:
                tar.extraction_filter = SvdDlFormat._gen_extract_filter(datadir=path, targets=targets)
                tar.extractall(path=path)


class SvdDl:

    _svd_resource_matcher = re.compile(
        r'^([a-zA-Z0-9_-]+)(\.([a-zA-Z0-9_-]+)){0,3}$')
    _svd_hash_matcher = re.compile(
        r'^[a-z0-9_-]{128}$')

    _download_formats = [
        SvdDlFormatZstd(),
        SvdDlFormatGzip(),
        SvdDlFormatPlain(),
    ]

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

    def dl_svd_to_local(self, dotted_name: str):
        if dotted_name not in self.index_json['files']:
            raise SvdDlError(f'SVD resource {dotted_name} could not be found in the index')

        svd_info = self.index_json['files'][dotted_name]
        svd_hash = svd_info['hash']

        if 'plain' not in svd_info["paths"]:
            raise SvdDlError(f'SVD resource {dotted_name} has no associated local path in the index')

        svd_path_part = svd_info["paths"]["plain"]
        svd_path = self._datapath(svd_path_part)

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
        errors = []
        for fmt in sorted(self._download_formats, key=lambda f: f.prio, reverse=True):
            if not fmt.available:
                continue
            if fmt.id not in svd_info["paths"]:
                continue

            svd_relname = svd_info["paths"][fmt.id]
            svd_url_fmt = self._repourl(svd_relname)
            svd_path_fmt = self._dataurl(svd_relname)

            try:
                self._urlretrieve_wrapper(svd_url_fmt, svd_path_fmt)
                try:
                    fmt._decompress_file(svd_path_fmt, svd_path)
                finally:
                    os.unlink(svd_path_fmt)

                if self._get_file_hash(svd_path) != svd_hash:
                    raise SvdDlError(f'Downloaded SVD file for "{dotted_name}" is corrupted.')

                return
            except Exception as e:
                errors.append(e)

        # Should not reach here
        raise SvdDlError(f'Failed to download {dotted_name}', errors)

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

            ef = self._datapath(v)
            if os.path.exists(ef):
                file_hash = self._get_file_hash(ef)
                if file_hash == file_info['hash']:
                    print(f'[+] SVD resource {k} in pack {dotted_name} already up-to-date')
                    correct_files.append(k)

        extract_files = {k: v for k, v in extract_files.items() if k not in correct_files}

        if len(extract_files) == 0:
            print(f'[+] Nothing left to update for pack: {dotted_name}')
            return

        errors = []
        for fmt in sorted(self._download_formats, key=lambda f: f.prio, reverse=True):
            if not fmt.available:
                continue
            if fmt.id not in pack_info['files']:
                continue

            fmt_info = pack_info["files"][fmt.id]

            # Download pack via format class
            pack_relname = fmt_info["name"]
            pack_url_fmt = self._repourl(pack_relname)
            pack_path_fmt = self._datapath(pack_relname)
            try:
                print(f'[i] Downloading pack "{dotted_name}" from "{pack_url_fmt}"')
                self._urlretrieve_wrapper(pack_url_fmt, pack_path_fmt)

                # Extract pack from .tar.zstd
                try:
                    fmt._decompress_archive(pack_path_fmt, LOCAL_DATA_DIR, extract_files)
                finally:
                    os.unlink(pack_path_fmt)

                # Verify extracted files
            except Exception as e:
                errors.append(e)

        # Should not reach here
        raise SvdDlError(f'Failed to download {dotted_name}', errors)

    def download_svd(self, download_string: str) -> None:
        download_files, download_packs = [], []
        os.makedirs(self.datadir, exist_ok=True)

        local_index = self._datapath(INDEX_JSON)
        local_hash = self._datapath(INDEX_HASH)

        print(f'[i] Downloading: index.hash')

        self._urlretrieve_wrapper(self._repourl(INDEX_HASH), local_hash)

        print(f'[i] Downloading: index.json')

        have_index = False

        if os.path.exists(local_index):
            if self._get_hash_from_index_hash(local_hash, INDEX_JSON) == self._get_file_hash(local_index):
                have_index = True

        if not have_index:
            for fmt in sorted(self._download_formats, key=lambda f: f.prio, reverse=True):
                if not fmt.available:
                    continue

                index_relname = fmt._add_fileext(INDEX_JSON)
                index_url = self._repourl(index_relname)
                index_path = self._datapath(index_relname)

                self._urlretrieve_wrapper(index_url, index_path)
                index_json_hash = self._get_file_hash(index_path)
                index_json_hash_valid = self._get_hash_from_index_hash(local_hash, target=index_relname)
                if index_json_hash != index_json_hash_valid:
                    raise SvdDlError(f'"{index_relname}" is corrupted.')

                try:
                    fmt._decompress_file(index_path, local_index)
                finally:
                    if index_path != local_index:
                        os.unlink(index_path)

                have_index = True
                break

        if not have_index:
            raise SvdDlError(f'Failed to refresh "{INDEX_JSON}"')

        # Check decompressed index.json
        print(f'[i] Validating: {INDEX_JSON}')
        index_json_hash = self._get_file_hash(local_index)
        index_json_hash_valid = self._get_hash_from_index_hash(local_hash, target=INDEX_JSON)
        if index_json_hash != index_json_hash_valid:
            raise SvdDlError(f'"{INDEX_JSON}" is corrupted.')

        with open(local_index, 'r') as f:
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
