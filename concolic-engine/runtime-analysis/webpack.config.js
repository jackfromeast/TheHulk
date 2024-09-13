import path from 'path';
import webpack from 'webpack';

// export default {
//   entry: './src/entry.js', // Ensure the correct path to your entry file
//   output: {
//     // filename: 'thehulk-runtime-analysis-api-count.bundle.js', // Output bundle file
//     filename: 'thehulk-runtime-analysis.bundle.js', // Output bundle file
//     path: path.resolve('dist'), // Output directory
//   },
//   plugins: [
//     new webpack.BannerPlugin({
//       banner: '// JALANGI DO NOT INSTRUMENT',
//       raw: true,
//       entryOnly: true
//     })
//   ],
//   mode: 'development', // Set the mode to 'development' or 'production'
// };


// export default {
//   entry: './src/entry.js', // Ensure the correct path to your entry file
//   output: {
//     filename: 'thehulk-runtime-analysis-api-count.bundle.js', // Output bundle file
//     path: path.resolve('dist'), // Output directory
//   },
//   plugins: [
//     new webpack.BannerPlugin({
//       banner: '// JALANGI DO NOT INSTRUMENT',
//       raw: true,
//       entryOnly: true
//     })
//   ],
//   mode: 'development', // Set the mode to 'development' or 'production'
// };


export default {
  entry: './src/entry.js', // Ensure the correct path to your entry file
  output: {
    filename: 'thehulk-runtime-analysis-verifier.bundle.js',
    path: path.resolve('dist'),
  },
  plugins: [
    new webpack.BannerPlugin({
      banner: '// JALANGI DO NOT INSTRUMENT',
      raw: true,
      entryOnly: true
    })
  ],
  mode: 'development', // Set the mode to 'development' or 'production'
};