// when true, nodejs will log the current step for each webpage to the console 
const DEBUG = true;         

// additional data that the crawler should store 
const COLLECT_AND_CREATE_PAGE = true;
const COLLECT_CONSOLE_LOGS = true;
const COLLECT_REQUESTS = true;
const COLLECT_WEB_STORAGE = false;
const COLLECT_COOKIES = false;
const COLLECT_HTML = true;
const COLLECT_CSS = true;
const COLLECT_SCRIPTS = true;
const EXTRACT_DOM_LOOKUPS = true;
const COLLECT_BROWSER_STDERR = true;
const COLLECT_BROWSER_STDOUT = true;
const COLLECT_XHR_REQUESTS = true;
const COLLECT_FETCH_REQUESTS = true;

const WAIT_BEFORE_NEXT_URL = 1000;

module.exports = {
    DEBUG,
    COLLECT_CONSOLE_LOGS,
    COLLECT_AND_CREATE_PAGE,
    COLLECT_REQUESTS,
    COLLECT_WEB_STORAGE,
    COLLECT_COOKIES,
    COLLECT_HTML,
    COLLECT_SCRIPTS,
    COLLECT_CSS,
    COLLECT_FETCH_REQUESTS,
    WAIT_BEFORE_NEXT_URL,
    EXTRACT_DOM_LOOKUPS,
    COLLECT_BROWSER_STDERR,
    COLLECT_BROWSER_STDOUT,
    COLLECT_XHR_REQUESTS
}