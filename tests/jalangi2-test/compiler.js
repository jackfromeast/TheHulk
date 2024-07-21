/**
 * @description
 * --------------------------------
 * This script generates test pages for Jalangi2 instrumentation and runtime.
 * 
 * @usage
 * --------------------------------
 * node compiler.js --test-scripts ./test-scripts --test-pages ./test-pages
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
function generateHTML(name, scriptRelPath, testCode) {
  const testPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOM Clobbering Micro Benchmarks</title>
    <link rel="stylesheet" href="../styles/styles.css">
</head>
<body>

<h1>Jalangi2 Instrumentation & Runtime Test Websites - Micro Benchmarks - ${name}</h1>

<section>
    <p>
        <span class="label">Description:</span>
       Test robustness of Jalangi2 framework.
    </p>
</section>

<section class="section">
<div class="column">
<p><span class="label">Testing Code:</span><br><br>
<pre>
${testCode}
</pre>
</div>
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

<h1>Jalangi2 Instrumentation & Runtime Test Websites - Micro Benchmarks - Index</h1>

<section>
  ${categorySections}
</section>

</body>
</html>`;

  return indexPage;
}

(function main() {
  const testScriptsDir = options.testScripts;
  const testPagesDir = options.testPages;

  // Read all directories in the test scripts directory
  const testModules = fs.readdirSync(testScriptsDir).filter(dir => fs.statSync(path.join(testScriptsDir, dir)).isDirectory());
  const pages = [];

  testModules.forEach(module => {
    const moduleDir = path.join(testScriptsDir, module);
    const jsTestNames = fs.readdirSync(moduleDir).filter(file => file.endsWith('.js'));

    let mainTestFile = null;
    let testCode = '';

    jsTestNames.forEach(jsTestName => {
      const jsFilePath = path.join(moduleDir, jsTestName);
      const jsFileContent = fs.readFileSync(jsFilePath, 'utf8');

      // Extract annotations
      const nameMatch = jsFileContent.match(/@Name: (.+)/);
      const fileMatch = jsFileContent.match(/@File: (.+)/);
      const importMatch = jsFileContent.match(/@Import: (.+)/);

      if (!nameMatch || !fileMatch || !importMatch) {
        console.error(`Failed to parse annotations from test script: ${jsTestName}`);
        return;
      }

      const name = nameMatch[1].trim();
      const file = fileMatch[1].trim();
      const importFlag = importMatch[1].trim().toLowerCase() === 'yes';

      if (importFlag) {
        mainTestFile = file;
        testCode = jsFileContent;
      }

      const outputScriptDir = path.join(testPagesDir, module, 'scripts');
      const outputScriptPath = path.join(outputScriptDir, file);

      if (!fs.existsSync(outputScriptDir)) {
        fs.mkdirSync(outputScriptDir, { recursive: true });
      }

      fs.writeFileSync(outputScriptPath, jsFileContent, 'utf8');
      console.log(`[+] Copied ${outputScriptPath}`);
    });

    if (mainTestFile) {
      const scriptRelPath = `./${module}/scripts/${mainTestFile}`;
      const htmlFileName = `${module}.html`;
      const htmlFilePath = path.join(testPagesDir, htmlFileName);
      const { html } = generateHTML(mainTestFile, scriptRelPath, testCode);

      fs.writeFileSync(htmlFilePath, html, 'utf8');
      console.log(`[+] Generated ${htmlFilePath}`);

      pages.push({ path: htmlFileName, name: mainTestFile, category: module });
    } else {
      console.error(`No main test file found for module: ${module}`);
    }
  });

  // Generate the index HTML content
  const indexHTML = generateIndexHTML(pages);
  const indexFilePath = path.join(testPagesDir, 'index.html');
  fs.writeFileSync(indexFilePath, indexHTML, 'utf8');
  console.log(`[+] Generated ${indexFilePath}`);
})();

