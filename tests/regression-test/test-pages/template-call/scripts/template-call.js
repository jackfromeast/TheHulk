/**
 * @Name: template-call-1
 * @File: template-call.js
 * @Import: Yes
 * @Refer: 
 *  - URL: https://jupyter.org/try-jupyter/extensions/jupyterlab-tour/static/581.612c2a7787620c9c4321.js?v=612c2a7787620c9c4321
 *  - Function: u({keyword: e, it: {errSchemaPath: t}}, {schemaPath: r, parentSchema: o})
 */
(function () {
  let t = "#";
  let e = "type";
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