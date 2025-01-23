import { TaintHelper } from "../taint-helper.js";
import { SafeBuiltins } from "../utils/safe-builtins.js";

/**
 * This class contains the list of functions that we know how to concretize its base and args.
 * 
 * - We don't want to blindly concretize all the base and args for all the unsupported functions 
 *   as it will cause performance issues and lead to taint loss.
 * - However, we also don't want to pass TaintValue to the unsupported functions as it will raise an 
 *   exception and break the program.
 * - Therefore, we need to concretize the base and args for the unsupported functions based on the 
 *   defined instructions. By default, we will concretize the base and args by one level, but for specific
 *   functions, we will concretize the base or args in a fine-grained manner.
 */
export class DefinedConcretizeBuiltinHelper {
  constructor() {
    this.prepare();
  }

  /**
   * Known functions that are explicitly handled for concretization.
   */
  knownConcretizedList = [
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

  concretizedDict = {
    // Browser APIs with specific concretization strategies
    "FinalizationRegistry.prototype.register": [FinalizationRegistry.prototype.register, "NONE"],
    "Performance.prototype.measure": [Performance.prototype.measure, "ARG1_OBJECT_RECURSIVE && ARGS_SELF"],
    "IDBObjectStore.prototype.get": [IDBObjectStore.prototype.get, "ARG0_ANY_RECURSIVE && ARGS_SELF"],
    "IDBObjectStore.prototype.put": [IDBObjectStore.prototype.put, "ARG0_ANY_RECURSIVE && ARGS_SELF"],
  };

  prepare() {
    // Check if PresentationRequest is defined
    if (typeof PresentationRequest !== 'undefined') {
      this.concretizedDict["PresentationRequest"] = [PresentationRequest, "ARG0_ARRAY_ONE_LEVEL || ARGS_SELF"];
    }
  }    

  // Method to check if a given function is in the concretized list
  isKnown(func) {
    return this.knownConcretizedList.includes(func);
  }

  /**
   * Validates a concretization strategy string.
   * @param {string} strategyString - The strategy string to validate.
   */
  validateStrategyString(strategyString) {
    const validStrategies = [
      'NONE', 'ARGS_SELF', 'BASE_SELF', 'ARG0_ARRAY_ONE_LEVEL', 'BASE_AND_ARGS_SELF', 'ARG1_OBJECT_RECURSIVE', 'ARG0_ANY_RECURSIVE'
    ];
    const strategyTokens = strategyString.split(/\s*(&&|\|\|)\s*/);
    for (const token of strategyTokens) {
      if (!validStrategies.includes(token.trim()) && !['&&', '||'].includes(token.trim())) {
        throw new Error(`Invalid concretization strategy: ${token}`);
      }
    }
  }

  /**
   * Generates a function that applies the concretization strategy.
   * @param {string} strategyString - The strategy string defining the concretization actions.
   * @returns {Function} A function that applies the concretization strategy.
   */
  makeStrategy(strategyString) {
    this.validateStrategyString(strategyString);

    const strategies = {
      'NONE': (base, args) => {
        return [base, args, true];
      },
      'ARGS_SELF': (base, args) => {
        args = Array.from(args).map(arg => TaintHelper.concreteHard(arg));
        return [base, args, true];
      },
      'BASE_SELF': (base, args) => {
        base = TaintHelper.concreteHard(base);
        return [base, args, true];
      },
      'ARG0_ARRAY_ONE_LEVEL': (base, args) => {
        if (Array.isArray(args[0])) {
          args[0] = args[0].map(item => TaintHelper.concreteHard(item));
          return [base, args, true];
        }
        return [base, args, false];
      },
      'ARG1_OBJECT_RECURSIVE': (base, args) => {
        if (typeof args[1] === 'object') {
          args[1] = TaintHelper.rconcreteHard(args[1]);
          return [base, args, true];
        }
        return [base, args, false];
      },
      'ARG0_ANY_RECURSIVE': (base, args) => {
        args[0] = TaintHelper.rconcreteHard(args[0]);
        return [base, args, true];    
      },
      'BASE_AND_ARGS_SELF': (base, args) => {
        base = TaintHelper.concreteHard(base);
        args = Array.from(args).map(arg => TaintHelper.concreteHard(arg));
        return [base, args, true];
      }
    };

    const applyStrategy = (strategy, base, args) => strategies[strategy](base, args);

    // Parse the strategyString and build a function that applies it
    const strategyFunction = (base, args) => {
      const tokens = SafeBuiltins.ArrayFilter.call(strategyString.split(/\s*(&&|\|\|)\s*/), Boolean);
      let result = [base, args, false];
      let skipNext = false;

      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i].trim();

        if (skipNext) {
          skipNext = false;
          continue;
        }

        if (strategies[token]) {
          const [newBase, newArgs, changed] = applyStrategy(token, ...result);
          result = [newBase, newArgs, changed || result[2]];

          // Handle OR condition: skip next strategy if this one succeeded
          if (tokens[i + 1] === '||' && changed) {
            skipNext = true;
          }
        }
      }

      return result;
    };

    return strategyFunction;
  }

  /**
   * Concretizes the base and args based on a specific strategy.
   * @param {Function} f - The function being concretized.
   * @param {*} base - The base object for the function.
   * @param {Arguments} args - The arguments passed to the function.
   * @returns {{ base: any, args: any[] }} The concretized base and arguments.
   */
  concrete(f, base, args) {
    let concretizationStrategy = "ARGS_SELF";

    // Determine the concretization strategy for the function
    for (const [key, value] of SafeBuiltins.ObjectEntries.call(null, this.concretizedDict)) {
      if (value[0] === f) {
        concretizationStrategy = value[1];
        break;
      }
    }

    const strategyFunction = this.makeStrategy(concretizationStrategy);
    const [base_c, args_c] = strategyFunction(base, args);

    return [base_c, args_c];
  }
}
