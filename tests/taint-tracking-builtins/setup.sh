node compiler.js --test-scripts ./test-scripts --test-pages ./test-pages
http-server test-pages -p 8001 -d false -c-1
# live-server test-pages --port=8002 --no-browser