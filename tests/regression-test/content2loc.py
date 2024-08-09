#!/usr/bin/env python3
"""
@description
-------------------------------------
This script finds the line and column of a given content in a file.

@usage
-------------------------------------
python3 content2loc.py --file-path /home/jackfromeast/Desktop/TheHulk/proxy-server/cache/jupyter.org/a6281b19ad2dde82be9e9d94dda81ba0.js --content "a.getErrorPath"
"""

import argparse

def find_content_position(file_path, content):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            column_number = line.find(content)
            if column_number != -1:
                print(f"Content found at line {line_number}, column {column_number + 1}")
                return
        
        print(f"Content '{content}' not found in the file.")
    except FileNotFoundError:
        print(f"The file {file_path} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description='Find the line and column of a given content in a file.')
    parser.add_argument('--file-path', type=str, required=True, help='Path to the file')
    parser.add_argument('--content', type=str, required=True, help='The content to search for in the file')
    
    args = parser.parse_args()
    
    find_content_position(args.file_path, args.content)

if __name__ == '__main__':
    main()
