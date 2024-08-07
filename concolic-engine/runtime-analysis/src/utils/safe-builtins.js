/**
 * @description
 * -------------------
 * In case the built-in functions are overwritten, we can use these safe built-ins to avoid any issues.
 */
export class SafeBuiltins {

  static ArrayForEach = Array.prototype.forEach;
  static ArrayFrom = Array.from;
  static ArrayIsArray = Array.isArray;
  static ArrayFilter = Array.prototype.filter;
  
  static ObjectEntries = Object.entries;

}