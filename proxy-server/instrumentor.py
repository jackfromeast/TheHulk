import os
import json
import shutil
import hashlib
import logging
import subprocess
from utils import load_config, resolve_url_to_path, hash_path, valid_file_path


class Instrumentor:
  """
  Description:
  --------------------------------
  This class is used to instrument the javascript code using Jalangi2.
  """
  def __init__(self, instrument_script_path, jalangi_args, cache):
    self.instrument_script_path = instrument_script_path
    self.jalangi_args = jalangi_args

    self.cache = cache
  
  def run_instrument_command(self):
    pass

  def instrument(self, url, content, file_type):
    ## TODO: Get the following information from the cache
    relative_path = resolve_url_to_path(url, file_type, content)['path']
    domain = relative_path.split('/')[0]
    weak_url_hash = hashlib.md5(relative_path.encode()).hexdigest()
    content_hash = hashlib.md5(content.encode()).hexdigest()

    ## TODO: Lookup the cache to see if the file has been instrumented
    # if self.cache.check_cache_file(domain, weak_url_hash, content_hash):

    original_file_name = f"{weak_url_hash}.{file_type}"
    instrumented_file_name = f"{weak_url_hash}_jalangi_.{file_type}"
    original_file_output_path = os.path.join(self.cache.cache_dir, domain, original_file_name)
    instrumented_file_output_path = os.path.join(self.cache.cache_dir, domain, instrumented_file_name)

    if not os.path.exists(os.path.dirname(original_file_output_path)):
      logger.error("The original file does not exist: %s", original_file_output_path)

    self.cache.update_cache_map(domain, weak_url_hash, url, 'instrumented', instrumented_file_output_path, None)
    
    ## Execute the instrument script
    sub_env = { 'JALANGI_URL': url }
    jalangi_args = ' '.join(self.jalangi_args)
    command = f"node {self.instrument_script_path} {jalangi_args} {original_file_output_path} --out {instrumented_file_output_path} --outDir {os.path.dirname(instrumented_file_output_path)}"

    try:
      subprocess.run(command, shell=True, env=sub_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      
      ## TODO: Neet to make sure the file has been instrumented
      # Assuming the command above does not raise an exception, we read the instrumented file
      with open(instrumented_file_output_path, 'r') as file:
          data = file.read()
      return data
    
    except subprocess.CalledProcessError as e:
      logger.error("Instrumentation failed: %s", str(e))
    
      return content

    