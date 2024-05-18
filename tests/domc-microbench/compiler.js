/**
 * Description:
 * --------------------------------
 * This script is used to generate the test pages from the scripts in the test-scripts folder
 * 
 * Usage:
 * --------------------------------
 * node compiler.js --test-scripts ./test-scripts/document --test-pages ./test-pages
 */

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');

const program = new Command();
program
  .option('--test-scripts <path>', 'Path to the directory containing test scripts')
  .option('--test-pages <path>', 'Path to the directory to output test pages')
  .parse(process.argv);

const options = program.opts();

if (!options.testScripts || !options.testPages) {
  console.error('Both --test-scripts and --test-pages options are required');
  process.exit(1);
}

// Function to generate HTML content
function generateHTML(jsFilePath, id, scriptRelPath, pages) {
  const jsFileContent = fs.readFileSync(jsFilePath, 'utf8');

  // Extract annotations
  const nameMatch = jsFileContent.match(/@Name: (.+)/);
  const sourceTypeMatch = jsFileContent.match(/@SourceType: (.+)/);
  const sourceCodeMatch = jsFileContent.match(/@SourceCode: (.+)/);
  const sinkTypeMatch = jsFileContent.match(/@SinkType: (.+)/);
  const sinkCodeMatch = jsFileContent.match(/@SinkCode: (.+)/);
  const codeMatch = jsFileContent.match(/(\/\/.*\n)*\n(.+)/s);

  if (!nameMatch || !sourceTypeMatch || !sourceCodeMatch || !sinkTypeMatch || !sinkCodeMatch || !codeMatch) {
      console.error(`Failed to parse annotations or code from ${jsFilePath}`);
      return;
  }

  const name = nameMatch[1].trim();
  const sourceType = sourceTypeMatch[1].trim();
  const sourceCode = sourceCodeMatch[1].trim();
  const sinkType = sinkTypeMatch[1].trim();
  const sinkCode = sinkCodeMatch[1].trim();
  const code = codeMatch[2].trim();

  // Generate navigation links
  const navLinks = pages.map(page => {
    if (page.id !== id) {
      return `<li><a href="${page.path}">Test ${page.id}: ${page.name}</a></li>`;
    }
    return '';
  }).join('\n');

  // HTML template
  const testPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DOM Clobbering Micro Benchmarks</title>
  <link rel="stylesheet" href="../styles/styles.css">
</head>
<body>

<h1>DOM Clobbering Websites - Micro Benchmarks - ${id}</h1>

<section>
  <p>
      <span class="label">Description:</span>
      Explore how DOM properties can be manipulated for benchmark testing in browser environments.
  </p>
</section>

<section class="section">
  <div class="column_double">
      <p><span class="label">Source:</span><br><br>
          <span class="indent">Type: ${sourceType}</span><br><br>
          <span class="indent">Code:</span>
          <pre class="indent">${sourceCode}</pre>
      </p>
  </div>
  <div class="column_double">
      <p><span class="label">Sink:</span><br><br>
          <span class="indent">Type: ${sinkType}</span><br><br>
          <span class="indent">Code:</span>
          <pre class="indent">${sinkCode}</pre>
      </p>
  </div>
</section>

<section class="section">
<div class="column">
<p><span class="label">Testing Code:</span><br><br>
<pre>
${code}
</pre>
</div>
</section>

<section>
  <h2>Other Tests</h2>
  <ul>
    ${navLinks}
  </ul>
</section>

<script src="${scriptRelPath}"></script>

</body>
</html>`;

  return { html: testPage, name: name };
}

// Function to generate index HTML content
function generateIndexHTML(pages) {
  const pageLinks = pages.map(page => `<li><a href="${page.path}">Test ${page.id}: ${page.name}</a></li>`).join('\n');
  
  const indexPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DOM Clobbering Micro Benchmarks</title>
  <link rel="stylesheet" href="./styles/styles.css">
</head>
<body>

<h1>DOM Clobbering Websites - Micro Benchmarks - Index</h1>

<section>
  <ul>
      ${pageLinks}
  </ul>
</section>

</body>
</html>`;

  return indexPage;
}

(function main(){
  // Read all JavaScript files in the test scripts directory and generate HTML files
  const jsTestNames = fs.readdirSync(options.testScripts).filter(file => file.endsWith('.js'));
  const pages = [];

  jsTestNames.forEach((jsTestName, index) => {
    const jsFilePath = path.join(options.testScripts, jsTestName);
    const outputScriptDir = path.join(options.testPages, 'scripts');
    const outputScriptPath = path.join(outputScriptDir, jsTestName);
    const htmlFileName = `${index + 1}-${jsTestName.slice(0, -3)}.html`;
    const htmlFilePath = path.join(options.testPages, htmlFileName);

    if (!fs.existsSync(outputScriptDir)) {
        fs.mkdirSync(outputScriptDir, { recursive: true });
    }

    fs.copyFileSync(jsFilePath, outputScriptPath);

    const scriptRelPath = `scripts/${jsTestName}`;
    const { html, name } = generateHTML(jsFilePath, index + 1, scriptRelPath, pages);

    fs.writeFileSync(htmlFilePath, html, 'utf8');
    console.log(`[+] Generated ${htmlFilePath}`);

    pages.push({ path: htmlFileName, title: `Test ${index + 1}`, name: name, id: index + 1 });
  });

  // Generate the index HTML content
  const indexHTML = generateIndexHTML(pages);
  const indexFilePath = path.join(options.testPages, 'index.html');
  fs.writeFileSync(indexFilePath, indexHTML, 'utf8');
  console.log(`[+] Generated ${indexFilePath}`);
})()
