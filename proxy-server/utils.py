import yaml
import os
import re
import hashlib

def load_config(file_path):
  try:
      with open(file_path, 'r') as file:
          config = yaml.safe_load(file)
          return config
  except FileNotFoundError:
      print(f"Error: The file {file_path} does not exist.")
      return {}
  except yaml.YAMLError as e:
      print(f"Error parsing YAML file: {e}")
      return {}



def resolve_url_to_path(c_url, c_type, c_content):
    is_data_uri = False
    found_index = c_url.find('://')
    
    if found_index == -1 or found_index >= 10:
        is_data_uri = True
        if c_url.startswith('data:'):
            data_uri_info = re.sub(r'[^A-Za-z0-9]', '.', c_url.split(';', 1)[0].split(',', 1)[0][:30])
            filename = f"{data_uri_info}.{hashlib.md5(c_url.encode()).hexdigest()[:6]}.txt"
        else:
            filename = f"data.{hashlib.md5(c_url.encode()).hexdigest()[:6]}.txt"
        filepath = os.path.join('_DataURI', filename)
    else:
        is_data_uri = False
        if 'http' in c_url.split('://')[0]:
            filepath = c_url.split('://')[1].split('?', 1)[0]
        else:
            filepath = c_url.replace('://', '---').split('?', 1)[0]

        if filepath.endswith('/'):
            filepath += 'index.html'
        filename = os.path.basename(filepath)
    
    filename = filename.split(';', 1)[0]
    filepath = os.path.join(os.path.dirname(filepath), filename)
    
    if '.' not in filename:
        extension = None
        if 'image' in c_type:
            if c_content.startswith('/'):
                extension = 'jpg'
            elif c_content.startswith('R'):
                extension = 'gif'
            elif c_content.startswith('i'):
                extension = 'png'
        elif 'stylesheet' in c_type or 'css' in c_type:
            extension = 'css'
        elif 'json' in c_type:
            extension = 'json'
        elif 'javascript' in c_type:
            extension = 'js'
        elif 'html' in c_type:
            extension = 'html'
        if not extension:
            extension = 'html'  # Default for unspecified types

        filepath += f'.{extension}'
        filename += f'.{extension}'
    
    filepath = re.sub(r'[:\\=*"?<>|]', '', filepath).replace('//', '/').replace('/./', '/').replace('/ /', '/')
    filename = re.sub(r'[:\\=*"?<>|]', '', filename)

    if '%' in filepath:
        try:
            ## TODO: decodeURIComponent is not in python
            filepath = decodeURIComponent(filepath)
            filename = decodeURIComponent(filename)
        except Exception as err:
            print(err)
    
    filepath = filepath.replace('//', '/').lstrip('/')
    
    return {
        'path': filepath,
        'name': filename,
        'dataURI': is_data_uri and c_url
    }



def valid_file_path(save_path):
    """
    Check if any part of the file path exceeds 254 characters.
    Returns True if all parts are valid, False otherwise.
    """
    # Split the path by '/' to get individual parts.
    parts = save_path.split('/')

    # Iterate over each part to check its length.
    for part in parts:
        # Check if any part is longer than 128 characters.
        if len(part) > 128:
            # If so, return false as it's invalid.
            return False

    # If all parts are valid, return true.
    return True


def hash_path(path):
    return hashlib.md5(path.encode()).hexdigest()