/**
 * @Name: template-object-conflict
 * @File: template-object-1.js
 * @Import: Yes
 * @Refer: 
 *  - URL: https://jupyter.org/try-jupyter/extensions/jupyterlab-tour/static/581.612c2a7787620c9c4321.js?v=612c2a7787620c9c4321
 *  - Function: u({keyword: e, it: {errSchemaPath: t}}, {schemaPath: r, parentSchema: o})
 */
(function () {
  let t = "#";
  let e = "type";
  // The following line will create the _templateObject due to the babel tranpilation
  // However, _templateObject is a global variable and it will be overwritten by other babel transpiled code
  // This is because the babel only see one file at a time
  foo`${t}/${e}`;

})();


function foo(e, ...t) {
  if (e[0] != '' || e[1] != '/' || e[2] != '') {
    throw new Error('Invalid template call');
  }

  if (t[0] != '#' || t[1] != 'type') {
    throw new Error('Invalid template call');
  }
}