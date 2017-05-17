# b2-python

Python module for Backblaze-B2 service

Example usage:

```python
>>> from b2 import B2
>>> backblaze = B2('account_id', 'account_key')
>>> bucket = backblaze.create_bucket('b2-api-test')
>>> bfile = backblaze.upload_file(bucket, '/path/to/file.zip')
>>> print('\n'.join(f.file_name for f in backblaze.list_file_names(bucket)))
file.zip
>>> print(backblaze.delete_file(bucket, 'file.zip'))
True
```

## This module is work in progress, and not expected to be anywhere near production state.
