import os
import json
import shutil
import hashlib
from logger import get_logger
import subprocess
from utils import load_config, resolve_url_to_path, hash_path, valid_file_path

logger = get_logger('Instrumentor')

class Instrumentor:
  """
  Description:
  --------------------------------
  This class is used to instrument the javascript code using Jalangi2.
  """
  def __init__(self, instrument_config, cache):

    self.instrument_script_path = instrument_config['INST_SCRIPT']
    self.jalangi_args = instrument_config['JALANGI_ARGS']
    self.save_failed_instrumentation = instrument_config['SAVE_FAILED_INSTRUMENTATION']
    self.fail_instrumentation_path = instrument_config['FAIL_INSTRUMENTATION_PATH']

    if (self.save_failed_instrumentation):
      os.makedirs(self.fail_instrumentation_path, exist_ok=True)

    self.cache = cache
  
  def run_instrument_command(self, url, original_file_output_path, instrumented_file_output_path):
    sub_env = { 'JALANGI_URL': url }
    jalangi_args = ' '.join(self.jalangi_args)
    command = f"node --max-old-space-size=32768 {self.instrument_script_path} {jalangi_args} {original_file_output_path} --out {instrumented_file_output_path} --outDir {os.path.dirname(instrumented_file_output_path)}"

    try:
      result = subprocess.run(command, shell=True, env=sub_env, check=True, timeout=80,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      
      if result.returncode == 0:
        return True
      else:
        logger.error("Instrumentation failed: %s", str(url))
        logger.error("Command: %s", command)
        if (self.save_failed_instrumentation):
          self.save_failed_instrumentation(command)

        return False

    except subprocess.TimeoutExpired:
      logger.error("Instrumentation timeout: %s", str(url))
      return False
    
    except subprocess.CalledProcessError as e:
      logger.error("Instrumentation failed: %s", str(url))
      if (self.save_failed_instrumentation):
        self.save_failed_instrumentation(command)

      return False

    except Exception as e:
      logger.error("Instrumentation failed: %s", str(url))
      if (self.save_failed_instrumentation):
        self.save_failed_instrumentation(command)

      return False
    

  def instrument(self, url, content, file_type):
    ## TODO: Get the following information from the cache
    relative_path = resolve_url_to_path(url, file_type, content)['path']
    domain = relative_path.split('/')[0]
    weak_url_hash = hashlib.md5(relative_path.encode()).hexdigest()
    content_hash = hashlib.md5(content.encode()).hexdigest()

    original_file_name = f"{weak_url_hash}.{file_type}"
    instrumented_file_name = f"{weak_url_hash}_jalangi_.{file_type}"
    original_file_output_path = os.path.join(self.cache.cache_dir, domain, original_file_name)
    instrumented_file_output_path = os.path.join(self.cache.cache_dir, domain, instrumented_file_name)


    # Use the cached instrumented file if it exists
    if os.path.exists(instrumented_file_output_path):
      # If the instrumented file bigger than the threshold, return the original file
      # if os.path.getsize(instrumented_file_output_path) > 10 * 1024 * 1024: # 10MB
      #   logger.warn("The instrumented file is too big: %s", instrumented_file_output_path)
      #   return content

      # logger.info("Return instrumented file in cache: %s", instrumented_file_output_path)
      with open(instrumented_file_output_path, 'r') as file:
          instrumented_content = file.read()
      return instrumented_content

    if not os.path.exists(os.path.dirname(original_file_output_path)):
      logger.error("The original file does not exist: %s", original_file_output_path)

    self.cache.update_cache_map(domain, weak_url_hash, url, 'instrumented', instrumented_file_output_path, None)

    ret = self.run_instrument_command(url, original_file_output_path, instrumented_file_output_path)

    if ret:
      with open(instrumented_file_output_path, 'r') as file:
        instrumented_content = file.read()
      
      return instrumented_content
    else:
      return content

  def save_failed_instrumentation(command):
    command_file_path = os.path.join(self.fail_instrumentation_path, 'failed_cmd.log')
    with open(command_file_path, 'a') as f:
        f.write(command + '\n')
