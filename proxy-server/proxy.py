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
import sys
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
    self.instrumentor = Instrumentor(self.instrument_config,
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

  def safe_get_response_text(self, flow):
    """
    Description:
    --------------------------------
    This function is used to get the text from the response. If the response is binary, it will return None.
    
    Sometimes the content has text/html type but actually is binary,
    And when trying to get the text from the response, it will raise an exception for mitmproxy.
    E.g. https://optimizationguide-pa.googleapis.com/downloads?name=1714403013&target=OPTIMIZATION_TARGET_NOTIFICATION_PERMISSION_PREDICTIONS
    """
    try:
      return flow.response.text
    except Exception as e:
      logger.warning("Failed to get text from the response (might be binary): %s", flow.request.url)
      return None

  @concurrent
  async def response(self, flow: http.HTTPFlow) -> None:
    """
    Description:
    --------------------------------
    This function is used to intercept the response from the server and instrument the javascript code using jalangi2.

    """
    
    if self.instrument_config['IGNORE_ENABLE'] == 'all':
      return
    elif self.instrument_config['IGNORE_ENABLE'] == 'true':
      if self.filter(flow.request.url):
        logger.info("Ignoring URL: %s", flow.request.url)
        return

    # Measurement
    response_arrive_time = time.time()
    response_decoded_time = 0
    cache_start_time = 0
    instrument_start_time = 0
    instrument_end_time = 0
    response_leave_time = 0

    try:
      try:
        flow.response.decode()
      except Exception as e:
        logger.warning("Failed to decode response: %s", flow.request.url)
        return

      response_decoded_time = time.time() # Measurement

      content_type = self.get_header_field(flow.response.headers, "content-type")
      short_url = len(flow.request.url) > 128 and flow.request.url[:128] + '...' or flow.request.url
      
      if content_type:
        if content_type.find('javascript') >= 0:
          # If URL ends with .json, we will not instrument it
          if flow.request.url.endswith('.json'):
            return

          logger.info("Response intercepted {JS}: %s", short_url)
          
          response_text = self.safe_get_response_text(flow)
          if response_text is None:
            return

          cache_start_time = time.time() # Measurement
          if self.cache_config['CACHE_ENABLE']:
            self.cache.save_cache_file(flow.request.url, response_text, 'js', 'raw')
          instrument_start_time = time.time() # Measurement
          flow.response.text = self.instrumentor.instrument(flow.request.url, response_text, 'js')
          instrument_end_time = time.time() # Measurement

        if content_type.find('html') >= 0:
          # If URL ends with .json, we will not instrument it
          if flow.request.url.endswith('.json'):
            return

          logger.info("Response intercepted {HTML}: %s", short_url)
          
          response_text = self.safe_get_response_text(flow)
          if response_text is None:
            return

          if self.cache_config['CACHE_ENABLE']:
            self.cache.save_cache_file(flow.request.url, response_text, 'html', 'raw')
          flow.response.text = self.instrumentor.instrument(flow.request.url, response_text, 'html')

    except Exception as e:
      logger.error("Exception raised when handling %s", flow.request.url)
      
      # return
      raise e
    
    response_leave_time = time.time()
    
    # Log the request process times
    logger.info(
    "Request URL: %s | Response decoded time duration: %.4f ms | Cache save time duration: %.4f ms | \
Instrumentation time duration: %.4f ms | Total processing time: %.4f ms",
    flow.request.url,
    (response_decoded_time - response_arrive_time) * 1000 if response_decoded_time > response_arrive_time else 0,
    (instrument_start_time - cache_start_time) * 1000 if instrument_start_time > cache_start_time else 0,
    (instrument_end_time - instrument_start_time) * 1000 if instrument_end_time > instrument_start_time else 0,
    (response_leave_time - response_arrive_time) * 1000
    )

addons = [
    JalangiResponseHandler(load_config('config.yaml'))
]