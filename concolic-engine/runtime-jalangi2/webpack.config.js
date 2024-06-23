const path = require('path');

module.exports = {
  entry: './src/entry.js', // Ensure the correct path to your entry file
  output: {
    filename: 'thehulk-jalangi2-runtime.bundle.js', // Output bundle file
    path: path.resolve('dist'), // Output directory
  },
  target: 'web',
  mode: 'development' // Set the mode to 'development' or 'production'
};

/**
 * @TODO
 * Currently, we don't pack esnstrument.js and astUtil.js which is necessary for dynamic generated JS
 * on the client side. Because, adding their dependencies (i.e. acorn, babel and esotope) is problematic.
 */
// export default {
//   entry: {
//     runtime: './src/entry.js',
//   },
//   output: {
//     filename: 'thehulk-jalangi2-runtime.bundle.js', 
//     path: path.resolve(__dirname, 'dist'), // Ensure the path is resolved relative to the current directory
//   },
//   mode: 'development',
//   resolve: {
//     extensions: ['.js', '*.mjs'],
//     fallback: {
//       "path": "path-browserify",
//       "process": "process/browser.js",
//       "assert": "assert",
//       "fs": false
//     }
//   },
//   target: 'web',
//   plugins: [
//     new webpack.ProvidePlugin({
//       process: 'process/browser.js', // Provide a polyfill for the 'process' module
//     }),
//   ],
// };