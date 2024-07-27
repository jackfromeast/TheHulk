/**
 * This class contains the list of functions that are known to be concretized
 */
export class ConcretizedFunctions {
  // List of functions known to be concretized
  static concretizedList = [
    // Array Object
    Array.isArray,
    Array.prototype.indexOf,
    Array.prototype.some,
    Array.prototype.includes,
    Array.prototype.find,
    Array.prototype.lastIndexOf,
    Array.prototype.at,

    // Object Object
    Object.hasOwnProperty,
    Object.freeze,
    Object.isFrozen,
    Object.isSealed,
    Object.isExtensible,
    Object.getOwnPropertyNames,
    Object.getOwnPropertySymbols,
    Object.getPrototypeOf,
    Object.is,
    Object.hasOwn,
    Object.create,
    

    // DOM APIs
    document.appendChild,
    document.createElement,
    document.removeChild,
    document.getElementsByTagName
  ];

  // Method to check if a given function is in the concretized list
  static isKnownConcretized(func) {
    return ConcretizedFunctions.concretizedList.includes(func);
  }
}
