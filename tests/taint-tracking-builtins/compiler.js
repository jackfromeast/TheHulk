/**
 * @description
 * --------------------------------
 * This script generates test pages for taint tracking builtins.
 * 
 * @usage
 * --------------------------------
 * node compiler.js --test-scripts ./test-scripts --test-pages ./test-pages
 */

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const { encode } = require('html-entities');

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
function generateHTML(testUnit, name, scriptRelPath, nextPage) {
  // Extract annotations
  const sourceTypeMatch = testUnit.match(/@SourceType: (.+)/);
  const sourceCodeMatch = testUnit.match(/@SourceCode: (.+)/);
  const sinkTypeMatch = testUnit.match(/@SinkType: (.+)/);
  const sinkCodeMatch = testUnit.match(/@SinkCode: (.+)/);
  const codeMatch = testUnit.match(/(\/\/.*\n)*\n(.+)/s);

  if (!sourceTypeMatch || !sourceCodeMatch || !sinkTypeMatch || !sinkCodeMatch || !codeMatch) {
    console.error(`Failed to parse annotations or code from test unit`);
    return;
  }

  const sourceType = sourceTypeMatch[1].trim();
  const sourceCode = sourceCodeMatch[1].trim();
  const sinkType = sinkTypeMatch[1].trim();
  const sinkCode = sinkCodeMatch[1].trim();
  const code = encode(codeMatch[2].trim());

  const navLinks = nextPage ? `<li><a href="../${nextPage.path}">Next Test: ${nextPage.name}</a></li>` : '';

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

<h1>Taint Tracking Test Websites - Micro Benchmarks - ${name}</h1>

<section>
    <p>
        <span class="label">Description:</span>
       Test the taint engine's ability on different builtins.
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
  <h2>Next Test</h2>
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
  const categorizedPages = pages.reduce((acc, page) => {
    if (!acc[page.category]) {
      acc[page.category] = [];
    }
    acc[page.category].push(page);
    return acc;
  }, {});

  const categorySections = Object.entries(categorizedPages)
    .map(([category, pages]) => {
      const pageLinks = pages.map(page => `<li><a href="${page.path}">Test: ${page.name}</a></li>`).join('\n');
      return `<h2>${category} Tests</h2><ul>${pageLinks}</ul>`;
    })
    .join('\n');

  const indexPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DOM Clobbering Micro Benchmarks</title>
  <link rel="stylesheet" href="./styles/styles.css">
</head>
<body>

<h1>Taint Tracking Test Websites - Micro Benchmarks - Index</h1>

<section>
  ${categorySections}
</section>

</body>
</html>`;

  return indexPage;
}

// Function to split the test script content into individual test units
function splitTestUnits(jsFileContent) {
  const testUnitRegex = /\/\*\*[\s\S]*?\*\/\s*\(function\s*\([\s\S]*?\}\)\(\);/g;
  return jsFileContent.match(testUnitRegex) || [];
}

(function main() {
  const testScriptsDir = options.testScripts;
  const testPagesDir = options.testPages;

  // Read all JavaScript files in the test scripts directory
  const jsTestNames = fs.readdirSync(testScriptsDir).filter(file => file.endsWith('.js'));
  const pages = [];
  const tests = [];

  jsTestNames.forEach(jsTestName => {
    const category = path.basename(jsTestName, '.js').split('-')[0];
    const jsFilePath = path.join(testScriptsDir, jsTestName);
    const jsFileContent = fs.readFileSync(jsFilePath, 'utf8');
    const testUnits = splitTestUnits(jsFileContent);

    testUnits.forEach(testUnit => {
      const nameMatch = testUnit.match(/@Name: (.+)/);
      if (!nameMatch) {
        console.error(`Failed to parse name from test unit`);
        return;
      }

      const name = nameMatch[1].trim();
      tests.push({ testUnit, name, category });
    });
  });

  tests.forEach((test, index) => {
    const { testUnit, name, category } = test;
    const nextPage = tests[index + 1] ? { path: `${tests[index + 1].category}/${tests[index + 1].name}.html`, name: tests[index + 1].name } : null;

    const outputScriptDir = path.join(testPagesDir, category, 'scripts');
    const outputScriptPath = path.join(outputScriptDir, `${name}.js`);
    const htmlFileName = `${category}/${name}.html`;
    const htmlFilePath = path.join(testPagesDir, htmlFileName);

    if (!fs.existsSync(outputScriptDir)) {
      fs.mkdirSync(outputScriptDir, { recursive: true });
    }

    fs.writeFileSync(outputScriptPath, testUnit, 'utf8');

    const scriptRelPath = `scripts/${name}.js`;
    const { html } = generateHTML(testUnit, name, scriptRelPath, nextPage);

    fs.writeFileSync(htmlFilePath, html, 'utf8');
    console.log(`[+] Generated ${htmlFilePath}`);

    pages.push({ path: htmlFileName, name: name, category: category });
  });

  // Generate the index HTML content
  const indexHTML = generateIndexHTML(pages);
  const indexFilePath = path.join(testPagesDir, 'index.html');
  fs.writeFileSync(indexFilePath, indexHTML, 'utf8');
  console.log(`[+] Generated ${indexFilePath}`);
})();
