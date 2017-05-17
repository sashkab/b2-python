"""Backblaze B2 API wrapper"""
from __future__ import absolute_import, print_function, unicode_literals

import json
from collections import namedtuple
import hashlib
import mimetypes

import py
import requests
from requests.auth import HTTPBasicAuth

B2_AUTH_API_ENDPOINT = 'https://api.backblazeb2.com/b2api/v1/b2_authorize_account'


B2Bucket = namedtuple('B2Bucket', ['bucket_name', 'bucket_id', 'bucket_type', 'bucket_info',
                                   'lifecycle_rules', 'revision', 'account_id'])
B2File = namedtuple('B2File', ['action', 'content_length', 'content_sha1', 'content_type',
                               'file_id', 'file_info', 'file_name', 'size', 'upload_timestamp'])


class B2Exception(Exception):
    """B2 API Exception"""

    def __init__(self, message, status, code, *args, **kwargs):
        self.message = message
        self.status = status
        self.code = code

    def __str__(self):
        return '{}: {}'.format(self.status, self.message)


class B2(object):
    """Backblaze B2 object"""

    _RENAMES = {
        # auth
        'absoluteMinimumPartSize': 'absolute_minimum_part_size',
        'accountId': 'account_id',
        'apiUrl': 'api_url',
        'authorizationToken': 'authorization_token',
        'downloadUrl': 'download_url',
        'minimumPartSize': 'minimum_part_size',
        'recommendedPartSize': 'recommended_part_size',

        # bucket list
        'bucketId': 'bucket_id',
        'bucketInfo': 'bucket_info',
        'bucketName': 'bucket_name',
        'bucketType': 'bucket_type',
        'lifecycleRules': 'lifecycle_rules',

        # file list
        'contentLength': 'content_length',
        'contentSha1': 'content_sha1',
        'contentType': 'content_type',
        'fileId': 'file_id',
        'fileInfo': 'file_info',
        'fileName': 'file_name',
        'uploadTimestamp': 'upload_timestamp',
    }

    debug = False
    buckets = None
    api_url = None
    account_id = None
    authorization_token = None

    def __init__(self, account_id, account_key):
        self.authorize_account(account_id, account_key)
        self.buckets = self.list_buckets()

    def __repr__(self):
        return 'B2(account_id="{account_id}", account_key="***")'.format(**self.__dict__)

    def authorize_account(self, account_id, account_key):
        """Login to B2 account.

        https://www.backblaze.com/b2/docs/b2_authorize_account.html
        """

        r = requests.get(B2_AUTH_API_ENDPOINT, auth=HTTPBasicAuth(account_id, account_key))
        if r.status_code == requests.codes.ok:
            data = json.loads(r.text)
            self.__dict__.update(self._rename_keys(data))  # NB: loading variables into self.
        else:
            if self.debug:
                print(r.text)
            data = json.loads(r.text)
            raise B2Exception(**data)

    def _rename_keys(self, d):
        """Rename keys of the dictionary according to the rename table"""

        return {self._RENAMES.get(k, k): v for k, v in d.items()}

    def _api_call(self, endpoint, params, headers=None):
        """Call API endpoint and return json object in case of success, otherwise raise."""

        if headers is None:
            headers = {'Authorization': self.authorization_token}
        r = requests.get("{}/{}".format(self.api_url, endpoint),
                         params=params,
                         headers=headers)
        if r.status_code == requests.codes.ok:
            if self.debug:
                print(r.text)
            return json.loads(r.text)
        else:
            if self.debug:
                print(r.text)
            data = json.loads(r.text)
            raise B2Exception(**data)

    def list_buckets(self):
        """Lists buckets in the B2 account.

        https://www.backblaze.com/b2/docs/b2_list_buckets.html
        """
        j = self._api_call('/b2api/v1/b2_list_buckets', params={'accountId': self.account_id})
        return [B2Bucket(**self._rename_keys(bucket)) for bucket in j['buckets']]

    def create_bucket(self, bucket_name, bucket_type='allPrivate'):
        """Creates a bucket.

        https://www.backblaze.com/b2/docs/b2_create_bucket.html
        """
        if self.debug:
            print(bucket_name, bucket_type)
        out = self._api_call('/b2api/v1/b2_create_bucket',
                             params={
                                 'accountId': self.account_id,
                                 'bucketName': bucket_name,
                                 'bucketType': bucket_type,
                             })
        bucket = B2Bucket(**self._rename_keys(out))
        self.buckets.append(bucket)
        return bucket

    def delete_bucket(self, bucket):
        """Deletes bucket.

        https://www.backblaze.com/b2/docs/b2_delete_bucket.html
        """

        out = self._api_call('/b2api/v1/b2_delete_bucket',
                             params={
                                 'accountId': self.account_id,
                                 'bucketId': bucket.bucket_id})
        self.buckets = [x for x in self.buckets if x.bucket_id != bucket.bucket_id]
        return True

    def get_upload_info(self, bucket):
        """Get upload token and url for bucket.

        https://www.backblaze.com/b2/docs/b2_get_upload_url.html
        """

        out = self._api_call('/b2api/v1/b2_get_upload_url',
                             params={'bucketId': bucket.bucket_id})
        return out['authorizationToken'], out['uploadUrl']

    def sha1sum(self, path):
        """Returns sha1 sum for the file in path."""

        path = py.path.local(path)
        hash = hashlib.sha1()
        with path.open('rb') as f:
            while True:
                buf = f.read(1024 * 1024 * 16)
                if not buf:
                    break
                hash.update(buf)
        return hash.hexdigest()

    def upload_file(self, bucket, path):
        """Upload file in path into bucket.

        https://www.backblaze.com/b2/docs/b2_upload_file.html
        """
        path = py.path.local(path)
        mimetypes.init()

        file_size = path.size()
        if file_size > 2**30:
            raise ValueError("File is too large")

        upload_token, upload_url = self.get_upload_info(bucket)

        with path.open('rb') as f:
            data = f.read()
            sha1sum = hashlib.sha1(data).hexdigest()

            headers = {
                'Authorization': upload_token,
                'X-Bz-File-Name': path.basename,
                'Content-Type': mimetypes.types_map.get(path.ext, 'application/octet-stream'),
                'X-Bz-Content-Sha1': sha1sum,
                'Content-Length': str(file_size),
                'X-Bz-Info-src_last_modified_millis': str(int(round(path.mtime() * 1000))),
            }

            r = requests.post(upload_url, data=data, headers=headers)

            if r.status_code == requests.codes.ok:
                if self.debug:
                    print(r.text)
                return json.loads(r.text)
            else:
                if self.debug:
                    print(r.text)
                data = json.loads(r.text)
                raise B2Exception(**data)

    def list_file_names(self, bucket):
        """Lists the names of all files in a bucket.

        https://www.backblaze.com/b2/docs/b2_list_file_names.html
        """

        j = self._api_call('/b2api/v1/b2_list_file_names',
                           params={'bucketId': bucket.bucket_id})

        return [B2File(**self._rename_keys(f)) for f in j['files']]

    def delete_file_version(self, bfile):
        """Deletes one version of a file from B2.

        https://www.backblaze.com/b2/docs/b2_delete_file_version.html
        """
        j = self._api_call('/b2api/v1/b2_delete_file_version',
                           params={
                               'fileName': bfile.file_name,
                               'fileId': bfile.file_id})

        return j['fileId'] == bfile.file_id

    def delete_file(self, bucket, file_name):
        """Deletes all versions of a file from B2."""

        deleted = False
        while True:
            files = [f for f in self.list_file_names(bucket) if f.file_name == file_name]
            if not files:
                break
            self.delete_file_version(files[0])
            deleted = True
        return deleted
