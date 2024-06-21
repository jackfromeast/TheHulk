module.exports = {
  setupFoxhoundTaintHandlerCb
};

const fs = require('fs').promises;
const path = require('path');


async function setupFoxhoundTaintHandlerCb(visitor, page) {
  await bindTaintHandlerForFoxHoundCb(visitor, page);
  await exposeHandlerToPageCb(visitor, page);
}

async function exposeHandlerToPageCb(visitor, page) {
  visitor.context.exposeBinding("__playwright_taint_report", async function (source, value) {
    if (visitor.config.collector.COLLECT_TAINTING_FLOWS){
      visitor.collected.curURLHash.taintflows.push(value)
    };
  });
}

async function bindTaintHandlerForFoxHoundCb(visitor, page) {
  const taintHandlerPath = path.resolve(visitor.config.others.FOXHOUND_TAINT_HANDLER_PATH);
  visitor.context.addInitScript({ path: taintHandlerPath});
}