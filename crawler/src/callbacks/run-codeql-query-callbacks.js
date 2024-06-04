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
    const resultPath = visitor.webpageFolder + `/${visitor.curURLHash}-ql-results.sarif`;
    const language = 'javascript';

    // Command to create the CodeQL database
    const createArgs = ['database', 'create', '--overwrite', '--language=' + language, '--source-root', repoPath, dbPath];

    visitor.logger.debug(`Creating CodeQL database: codeql ${createArgs.join(' ')}`);

    // Executing the database creation command
    const createProcess = spawn('codeql', createArgs);

    createProcess.on('exit', (code) => {
        if (code === 0) {
            visitor.logger.debug(`CodeQL database created at ${dbPath}`);
            
            // Command to run the CodeQL query
            const runArgs = ['database', 'analyze', dbPath, qlPath, '--format=sarif-latest', '-o', resultPath];
            const runProcess = spawn('codeql', runArgs);

            visitor.logger.debug(`Starting Analysis on CodeQL: codeql ${runArgs.join(' ')}`);

            const timeout = 1800000; // 30 mins timeout
            const timeoutId = setTimeout(() => {
                visitor.logger.error(`Query run process exceeded timeout of ${timeout}ms and will be terminated: codeql ${runArgs.join(' ')}`);
                runProcess.stdin.end();
                runProcess.kill('SIGKILL');
            }, timeout);

            runProcess.on('exit', (code) => {
                if (code === 0) {
                    clearTimeout(timeoutId);
                    visitor.logger.debug(`CodeQL result created at ${resultPath}`);
                } else {
                    clearTimeout(timeoutId);
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