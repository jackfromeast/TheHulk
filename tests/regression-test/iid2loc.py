#!/usr/bin/env python3
"""
@description
-------------------------------------
This script finds the original code context given the instrumented file path and iid.

@usage
-------------------------------------
python3 iid2loc.py --file-path /path/to/instrumented/file.js --iid 1234
or
iid2loc --file-path /path/to/instrumented/file.js --iid 1234 
(as the file has been soft linked to the /usr/local/bin)

@example
-------------------------------------
iid2loc /home/jackfromeast/Desktop/TheHulk/proxy-server/cache/jupyter.org/a6281b19ad2dde82be9e9d94dda81ba0_jalangi_.js 83025
"""
import argparse
import os
import json

def find_error_position(file_path, error_position):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        line_number = error_position['line']
        column_number = error_position['column']

        # Ensure the line number is within the file
        if line_number > len(lines):
            print(f"Line number {line_number} exceeds the total number of lines in the file.")
            return

        error_line = lines[line_number - 1]

        # Ensure the column number is within the line
        if column_number > len(error_line):
            print(f"Column number {column_number} exceeds the length of the line.")
            return

        # Display the surrounding context of the error
        start_index = max(0, column_number - 50)
        end_index = min(len(error_line), column_number + 50)
        error_context = error_line[start_index:end_index]

        print(f"Error found at line {line_number}, column {column_number}:")
        print(f"Context: {error_context}")
    except FileNotFoundError:
        print(f"The file {file_path} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

def find_original_context(instrumented_file_path, iid):
    try:
      # Derive the original file path and the JSON map path
      transpiled_file_path = instrumented_file_path.replace('_jalangi_', '_es5_transpiled_')
      original_file_path = instrumented_file_path.replace('_jalangi_', '')
      json_map_path = original_file_path.replace('.js', '_jalangi_.json')

      # Load the mapping from the JSON file
      with open(json_map_path, 'r') as json_file:
          mapping = json.load(json_file)

      # Check if the IID is in the mapping
      if str(iid) not in mapping:
          print(f"IID {iid} not found in the mapping.")
          return

      # Get the original line and column positions from the mapping
      original_line_start, original_col_start, original_line_end, original_col_end = mapping[str(iid)]

      # Load the original file contents
      with open(transpiled_file_path, 'r') as original_file:
          original_lines = original_file.readlines()

      # Ensure the line number is within the file
      if original_line_start > len(original_lines):
          print(f"Line number {original_line_start} exceeds the total number of lines in the original file.")
          return

      # Get the content of the starting line
      original_line_content = original_lines[original_line_start-1]

      # Calculate the context indices
      original_start_index = max(0, original_col_start - 100)
      original_end_index = min(len(original_line_content), original_col_start + 100)
      original_context = original_line_content[original_start_index:original_end_index]

      # Print the original context
      print(f"Original context found at line {original_line_start-1}, columns {original_col_start}-{original_col_end}:")
      print(f"Context: {original_context}")
    except FileNotFoundError as e:
      print(f"File not found: {e}")
    except json.JSONDecodeError:
      print(f"Error decoding the JSON file at {json_map_path}.")
    except Exception as e:
      print(f"An error occurred: {e}")


def main():
    parser = argparse.ArgumentParser(description='Find the original code context given the instrumented file path and iid.')
    parser.add_argument('file_path', type=str, help='Path to the instrumented JavaScript file')
    parser.add_argument('iid', type=int, help='The IID to look up in the JSON map')

    args = parser.parse_args()
    
    find_original_context(args.file_path, args.iid)

if __name__ == '__main__':
    main()
