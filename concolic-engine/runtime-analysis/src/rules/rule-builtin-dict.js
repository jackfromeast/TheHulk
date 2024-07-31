/**
 * This class contains the list of functions that are known to be concretized
 */
export class ConcretizedBuiltins {
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
    return ConcretizedBuiltins.concretizedList.includes(func);
  }
}

/**
 * This class contains the list of functions that are known will change the base object
 * 
 * Note that, function in the list doesn't means that we can only create NoneRule for it.
 * In the most case, runOriginalFunc will depth=1 will be fine.
 */
export class BaseClobberableBuiltins {
  static baseClobberableList = [
    // Array
    Array.prototype.push,
    Array.prototype.pop,
    Array.prototype.shift,
    Array.prototype.unshift,
    Array.prototype.reverse,
    Array.prototype.sort,
    Array.prototype.splice,
    Array.prototype.fill,

    // Set
    Set.prototype.add,
    Set.prototype.delete,
    Set.prototype.clear,

    // Map
    Map.prototype.set,
    Map.prototype.delete,
    Map.prototype.clear,

    // WeakMap
    WeakMap.prototype.set,
    WeakMap.prototype.delete,

    // WeakSet
    WeakSet.prototype.add,
    WeakSet.prototype.delete,

    // Object
    Object.assign,
    Object.defineProperty,
    Object.defineProperties,
    Object.setPrototypeOf,
  ];

  // Method to check if a given function is in the concretized list
  static isKnownBaseClobberable(func) {
    return BaseClobberableBuiltins.baseClobberableList.includes(func);
  }
}


/**
 * This class contains the list of functions that are known will change the arguments object
 */
export class ArgumentsClobberableBuiltins {
  static argumentsClobberableList = [
    // None specifically identified based on typical ECMAScript operations
  ];

  // Method to check if a given function is in the concretized list
  static isKnownArgsClobberable(func) {
    return ArgumentsClobberableBuiltins.argumentsClobberableList.includes(func);
  }
}
