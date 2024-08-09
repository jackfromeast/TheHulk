/**
 * @Name: instrument-import-1
 * @File: import1.js
 * @Import: Yes
 */
(async function () {
  console.log('Executing import1.js');
  try {
    await import('./import2.js');
    console.log('Successfully imported import2.js');
  } catch (error) {
    console.error('Failed to import import2.js:', error);
  }
})();