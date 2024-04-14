const { execSync, exec } = require('child_process');
const path = require('path');

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * Create a CodeQL database given the visitor.webpageFolder/source as the codebase 
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function createCodeQLDatabaseCb(visitor, _){
    const repoPath = visitor.webpageFolder + '/source'; // Adjust according to actual structure.
    const dbPath = visitor.webpageFolder + `/${path.basename(visitor.webpageFolder)}-codeql-db-2`; // Customize the DB path as needed.

    const language = 'javascript'; // Set the programming language as per your needs.

    visitor.logger.debug(`Creating CodeQL database for language: ${language} in ${repoPath}`);

    // Construct the CodeQL database creation command.
    const command = `codeql database create --overwrite --language="${language}" --source-root "${repoPath}" "${dbPath}"`;

    await exec(command, {maxBuffer: 1024 * 500}, (error, stdout, stderr) => {
        if (error) {
            visitor.logger.error(`Error: ${error.message}`);
            return;
        }
        if (stderr) {
            visitor.logger.error(`Stderr: ${stderr}`);
            return;
        }
        visitor.logger.debug(`Stdout: ${stdout}`);
        visitor.logger.debug(`CodeQL database created at ${dbPath}`);
    });
}

// let visitor = {};
// visitor.logger = console;
// visitor.webpageFolder = '/home/jackfromeast/Desktop/SafeLookup/output/html-injection/stackedit.io';
// createCodeQLDatabaseCb(visitor, null);


module.exports = {
    createCodeQLDatabaseCb
};
