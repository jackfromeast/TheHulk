"""
  Description:
  --------------------------------

  This file is used to set up the proxy server for the Jalangi2 instrumentation. The proxy will intercept all the responses and instrument the javascript code using jalangi2. The instrumented code will be sent back to the client, while saved in the proxy server for caching. At the next time, if the response has arrived again, the proxy will directly return the instrumented code from the cache without re-instrumenting it.

  This file will be used as the addon (filter script) for the mitmdump.

  The implementation is based on https://github.com/Samsung/jalangi2/blob/master/scripts/proxy.py

  Usage:
  --------------------------------
  python3 proxy.py --conf=config.yaml

"""
import os
import time
import json
import shutil
import hashlib
import logging
import subprocess
from cache import Cache
from utils import load_config, resolve_url_to_path
from mitmproxy import http, ctx
from mitmproxy.script import concurrent


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Proxy')


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

    

class JalangiResponseHandler:
  """
  Description:
  --------------------------------
  This class is used to set up the proxy server for the Jalangi2 instrumentation.
  """

  def __init__(self, config):
    self.instrument_config = config['instrumentation']
    self.cache_config = config['cache']
    self.ignore = self.instrument_config['IGNORE_URLS']

    self.cache = Cache(self.cache_config['CACHE_PATH'])
    self.instrumentor = Instrumentor(self.instrument_config['INST_SCRIPT'],
                                     self.instrument_config['JALANGI_ARGS'],
                                     self.cache)

  def filter(self, url):
    if url in self.ignore:
      return True
    return False
  
  def get_header_field(self, headers, header_name):
    for key in headers.keys():
      if key.lower() == header_name.lower():
        return headers[key].lower()
    return None

  @concurrent
  async def response(self, flow: http.HTTPFlow) -> None:

    if self.instrument_config['IGNORE_ENABLE'] == 'all':
      return
    elif self.instrument_config['IGNORE_ENABLE'] == 'true':
      if self.filter(flow.request.url):
        logger.info("Ignoring URL: %s", flow.request.url)
        return

    try:
      flow.response.decode()

      content_type = self.get_header_field(flow.response.headers, "content-type")
      csp_key = self.get_header_field(flow.response.headers, "content-security-policy")
      
      if content_type:
        if content_type.find('javascript') >= 0:
          logger.info("Response intercepted: %s", flow.request.url)
          if self.cache_config['CACHE_ENABLE']:
            self.cache.save_cache_file(flow.request.url, flow.response.text, 'js', 'raw')
          flow.response.text = self.instrumentor.instrument(flow.request.url, flow.response.text, 'js')

        if content_type.find('html') >= 0:
          logger.info("Response intercepted: %s", flow.request.url)
          if self.cache_config['CACHE_ENABLE']:
            self.cache.save_cache_file(flow.request.url, flow.response.text, 'html', 'raw')
          flow.response.text = self.instrumentor.instrument(flow.request.url, flow.response.text, 'html')
      
      # Disable the content security policy since it may prevent jalangi from executing
      if csp_key:
        flow.response.headers.pop(csp_key, None)

    except Exception as e:
      logger.error("Exception raised when handling %s: %s", flow.request.url, str(e))
      return



addons = [
    JalangiResponseHandler(load_config('config.yaml'))
]


