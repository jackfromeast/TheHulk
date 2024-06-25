// Import Terser so we can use it
const { minify } = require('terser');

// Import fs so we can read/write files
const fs = require('fs');

// Define the config for how Terser should minify the code
// This is set to how you currently have this web tool configured
const config = {
  compress: {
    dead_code: false,
    drop_console: false,
    drop_debugger: false,
    keep_classnames: true,
    keep_fargs: true,
    keep_fnames: true,
    keep_infinity: true
  },
  mangle: {
    eval: false,
    keep_classnames: false,
    keep_fnames: false,
    toplevel: false,
    safari10: false
  },
  module: false,
  sourceMap: false,
  output: {
    comments: 'some'
  }
};


(async function main(){
  // Load in your code to minify
  const code = fs.readFileSync('/home/jackfromeast/Desktop/TheHulk/proxy-server/cache/www.youtube.com/d842e6c5816b064198143e38f1266ba5_jalangi_.js', 'utf8');

  // Minify the code with Terser
  const minified = await minify(code, config);

  // Save the code!
  fs.writeFileSync('/home/jackfromeast/Desktop/TheHulk/proxy-server/cache/www.youtube.com/d842e6c5816b064198143e38f1266ba5_jalangi_.min.js', minified.code);

  // Size before and after
  console.log(`Before: ${code.length} bytes`);
  console.log(`After: ${minified.code.length} bytes`);
})()