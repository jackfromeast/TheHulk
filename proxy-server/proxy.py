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
from logger import get_logger
from cache import Cache
from instrumentor import Instrumentor
from utils import load_config, resolve_url_to_path
from mitmproxy import http, ctx
from mitmproxy.script import concurrent


logger = get_logger('Proxy')


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
      try:
        flow.response.decode()
      except Exception as e:
        logger.warning("Failed to decode response: %s", flow.request.url)
        return

      content_type = self.get_header_field(flow.response.headers, "content-type")
      # csp_key = self.get_header_field(flow.response.headers, "content-security-policy")
      
      short_url = len(flow.request.url) > 128 and flow.request.url[:128] + '...' or flow.request.url
      
      if content_type:
        if content_type.find('javascript') >= 0:
          logger.info("Response intercepted: %s", short_url)
          if self.cache_config['CACHE_ENABLE']:
            self.cache.save_cache_file(flow.request.url, flow.response.text, 'js', 'raw')
          flow.response.text = self.instrumentor.instrument(flow.request.url, flow.response.text, 'js')

        if content_type.find('html') >= 0:
          logger.info("Response intercepted: %s", short_url)
          if self.cache_config['CACHE_ENABLE']:
            self.cache.save_cache_file(flow.request.url, flow.response.text, 'html', 'raw')
          flow.response.text = self.instrumentor.instrument(flow.request.url, flow.response.text, 'html')
      
      # Moved this part to the browser by setting CSP bypass
      # Disable the content security policy since it may prevent jalangi from executing
      # if csp_key:
      #   flow.response.headers.pop(csp_key, None)

    except Exception as e:
      logger.error("Exception raised when handling %s", short_url)
      return
      # raise e


addons = [
    JalangiResponseHandler(load_config('config.yaml'))
]


