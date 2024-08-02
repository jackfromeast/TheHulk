import { TaintHelper } from "../taint-helper.js";

/**
 * This class contains the list of functions that we know how to concretize its base and args
 * 
 * - We don't want to blindly concretize all the base and args for all the unsupported functions 
 *   as it will cause performance issues and lead to taint loss.
 * - However, we also don't want to pass TaintValue to the unsupported functions as it will raise an 
 *   exception and break the program.
 * - Therefore, we need to concretize the base and args for the unsupported functions based on the 
 *   defined instructions. By default, we will concretize the base and args by one level, but for specific
 *   fucntions, we will concretize the base or args in a fine grain manner.
 */
export class DefinedConcretizeBuiltins {
  /**
   * Known functions that are explicitly handled for concretization.
   */
  static knownConcretizedList = [
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
  static isKnown(func) {
    return DefinedConcretizeBuiltins.knownConcretizedList.includes(func);
  }

  static concretizedDict = {
    // Browser APIs with specific concretization strategies
    "PresentationRequest": [PresentationRequest, "ARG0_ARRAY_ONE_LEVEL"]
  };

  /**
   * Validates a concretization strategy string.
   * @param {string} strategyString - The strategy string to validate.
   */
  static validateStrategyString(strategyString) {
    const validStrategies = [
      'ARGS_SELF', 'BASE_SELF', 'ARG0_ARRAY_ONE_LEVEL', 'BASE_AND_ARGS_SELF'
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
  static makeStrategy(strategyString) {
    DefinedConcretizeBuiltins.validateStrategyString(strategyString);

    const strategies = {
      'ARGS_SELF': (base, args) => {
        args = Array.from(args).map(arg => TaintHelper.concreteHard(arg));
        return [base, args];
      },
      'BASE_SELF': (base, args) => {
        base = TaintHelper.concreteHard(base);
        return [base, args];
      },
      'ARG0_ARRAY_ONE_LEVEL': (base, args) => {
        if (Array.isArray(args[0])) {
          args[0] = args[0].map(item => TaintHelper.concreteHard(item));
        }else {
          args = Array.from(args).map(arg => TaintHelper.concreteHard(arg));
        }
        return [base, args];
      },
      'BASE_AND_ARGS_SELF': (base, args) => {
        base = TaintHelper.concreteHard(base);
        args = Array.from(args).map(arg => TaintHelper.concreteHard(arg));
        return [base, args];
      }
    };

    let modifiedStrategyString = strategyString;

    Object.keys(strategies).forEach(key => {
      const regex = new RegExp(`\\b${key}\\b`, 'g');
      modifiedStrategyString = modifiedStrategyString.replace(regex, `strategies.${key}`);
    });

    const strategyFunction = new Function('strategies', 'base', 'args', `
      return ${modifiedStrategyString}(base, args);
    `);

    return strategyFunction.bind(null, strategies);
  }

  /**
   * Concretizes the base and args based on a specific strategy.
   * @param {Function} f - The function being concretized.
   * @param {*} base - The base object for the function.
   * @param {Arguments} args - The arguments passed to the function.
   * @returns {{ base: any, args: any[] }} The concretized base and arguments.
   */
  static concrete(f, base, args) {
    let concretizationStrategy = "ARGS_SELF";

    // Determine the concretization strategy for the function
    for (const [key, value] of Object.entries(DefinedConcretizeBuiltins.concretizedDict)) {
      if (value[0] === f) {
        concretizationStrategy = value[1];
        break;
      }
    }

    const strategyFunction = DefinedConcretizeBuiltins.makeStrategy(concretizationStrategy);
    const [base_c, args_c] = strategyFunction(base, args);

    return [base_c, args_c];
  }
}
