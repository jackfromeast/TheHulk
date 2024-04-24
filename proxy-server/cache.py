import os
import json
import shutil
import hashlib
import logging
from utils import load_config, resolve_url_to_path, hash_path, valid_file_path


class Cache:
  """
  Description:
  --------------------------------
  This class is used to manage the cache of the instrumented code.
  It helps to manage the cache filesystem by maintaining the cache 
  directory and loading the cache file.

  Each URL resource will be saved in the cache directory based on the URL
  However, sometimes the parts of the URL are too long, so we need to hash it
  
  E.g. 
  https://example.com/1234567890/index.js will be saved as:
  cache/example.com/1234567890/index.js

  E.g. https://example.com/AAAA**1000**BBBB/index.js will be saved as:
  cache/example.com/long_name_resources/$HASH.js

  To keep track of the URL, save_path, and the content hash, we need to
  maintain the cache_map and cache_long_filename_map. In the cache_map,
  we store the URL, save_path (raw_file and instrumented) and content hash
  of the raw resource. The cache_map will be saved as json file in the
  cache directory.
  """
  def __init__(self, cache_dir):
    self.cache_dir = cache_dir
    self.cache_map_path = os.path.join(self.cache_dir, 'cache_map.json')
    self.cache_map = {}

    if not os.path.exists(self.cache_dir):
      os.makedirs(self.cache_dir)
    
    self.clean_cache()
    self.load_cache_map()

  def clean_cache(self):
    shutil.rmtree(self.cache_dir, ignore_errors=True)
    os.makedirs(self.cache_dir)

  def load_cache_map(self):
    if os.path.exists(self.cache_map_path):
      with open(self.cache_map_path, 'r') as file:
        self.cache_map = json.load(file)

  def save_cache_map(self):
    with open(self.cache_map_path, 'w') as file:
      json.dump(self.cache_map, file, indent=4)

  def save_per_site_cache_map(self, domain, data):
    save_path = os.path.join(self.cache_dir, domain, 'site_cache_map.json')
    with open(save_path, 'w') as file:
      json.dump(data, file, indent=4)
  
  def update_cache_map(self, domain, weak_url_hash, url, status, save_path, content_hash):
    if domain not in self.cache_map:
      self.cache_map[domain] = {}
    
    if status == "instrumented":
      self.cache_map[domain][weak_url_hash]['instrumented'] = save_path
    else:
      self.cache_map[domain][weak_url_hash] = {
        'url': url,
        'resource_hash': content_hash,
        status: save_path
      }

    # self.save_cache_map()
    logging.info(f"Cache map updated: {self.cache_map[domain]}") 
    self.save_per_site_cache_map(domain, self.cache_map[domain])

  """
  Description:
  --------------------------------
  This function is used to save the cache file in the cache directory.

  Parameters:
  --------------------------------
  @url: The URL of the resource
  @content: The content of the resource
  @filetype: The type of the resource (e.g. js, css, html)
  @status: The status of the resource (e.g. raw, instrumented)
  """
  def save_cache_file(self, url, content, filetype, status):
    relative_path = resolve_url_to_path(url, filetype, content)['path']
    domain = relative_path.split('/')[0]
    weak_url_hash = hashlib.md5(relative_path.encode()).hexdigest()
    content_hash = hashlib.md5(content.encode()).hexdigest()
    
    # Here we are not use the url hash but the relative path hash
    # Since the url may has query parameters
    save_path = os.path.join(
      self.cache_dir,
      domain,                                       # domain name    
      weak_url_hash + '.' + filetype                # hash + filetype
    )

    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    with open(save_path, 'w') as file:
      file.write(content)

    self.update_cache_map(domain, weak_url_hash, url, status, save_path, content_hash)
  