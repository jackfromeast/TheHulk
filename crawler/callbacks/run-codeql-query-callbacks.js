const { spawn } = require('child_process');
const path = require('path');

/**
 * The callback function takes the visitor and page objects as arguments.
 * 
 * Create a CodeQL database given the visitor.webpageFolder/source as the codebase,
 * and then run a CodeQL query on this database.
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function createAndRunCodeQLQueryCb(visitor, _){
    const repoPath = visitor.webpageFolder + '/source';
    const dbPath = visitor.webpageFolder + `/${path.basename(visitor.webpageFolder)}-codeql-db`;
    const qlBasePath = visitor.config.others.CODEQL_QUERY_SAVE_PATH;
    const qlPath = qlBasePath + `/${visitor.domain}-${visitor.curURLHash}-undef.ql`;
    const resultPath = visitor.webpageFolder + '/ql-results.bqrs';
    const language = 'javascript';

    visitor.logger.debug(`Creating CodeQL database for language: ${language} in ${repoPath}`);

    // Command to create the CodeQL database
    const createArgs = ['database', 'create', '--overwrite', '--language=' + language, '--source-root', repoPath, dbPath];

    // Executing the database creation command
    const createProcess = spawn('codeql', createArgs);

    createProcess.on('exit', (code) => {
        if (code === 0) {
            visitor.logger.debug(`CodeQL database created at ${dbPath}`);
            
            // Command to run the CodeQL query
            const runArgs = ['query', 'run', qlPath, '-d', dbPath, '-o', resultPath];
            const runProcess = spawn('codeql', runArgs);

            runProcess.on('exit', (code) => {
                if (code === 0) {
                    visitor.logger.debug(`CodeQL result created at ${resultPath}`);
                } else {
                    visitor.logger.error(`Query run process exited with code ${code}`);
                }
            });
        } else {
            visitor.logger.error(`Database creation process exited with code ${code}`);
        }
    });
}

module.exports = {
    createAndRunCodeQLQueryCb
};