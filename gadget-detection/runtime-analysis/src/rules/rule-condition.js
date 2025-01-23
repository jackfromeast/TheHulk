import { TaintHelper } from '../taint-helper.js';
import { WrappedValue, _, TaintValue } from '../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../values/taint-info.js';

/**
 * Condition Barrier Class
 * 
 * @description
 * --------------------------------
 * This class generates the condition barrier for the taint propagation rules.
 * 
 * Each condition barrier is a function that takes the base, arguments, and reflected object
 * and returns a boolean value to indicate whether the taint propagation rule should be applied.
 * 
 * Currently, we support the following condition barriers:
 * - BASE_TAINTED: The base object is tainted.
 * - ANY_ARGS_TAINTED: Any of the arguments is tainted.
 * - FIRST_ARG_TAINTED: The first argument is tainted.
 * - SECOND_ARG_TAINTED: The second argument is tainted.
 * - LAST_ARG_TAINTED: The last argument is tainted.
 */
export class ConditionBuilder {
  static BASE_TAINTED_RECURSIVE(base, args, reflected) {
    return TaintHelper.risTainted(base);
  }

  static BASE_TAINTED(base, args, reflected) {
    return TaintHelper.isTainted(base);
  }

  static ANY_ARGS_TAINTED(base, args, reflected) {
    return TaintHelper.isAnyArgumentsTainted(args, reflected);
  }

  static ANY_ARGS_TAINTED_RECURSIVE(base, args, reflected) {
    return TaintHelper.rgetTaintInfoisAnyArgumentsTainted(args, reflected);
  }

  static FIRST_ARG_TAINTED(base, args, reflected) {
    return args.length > 0 && TaintHelper.isTainted(args[0]);
  }

  static FIRST_ARG_TAINTED_RECURSIVE(base, args, reflected) {
    return args.length > 0 && TaintHelper.risTainted(args[0]);
  }

  static SECOND_ARG_TAINTED(base, args, reflected) {
    return args.length > 1 && TaintHelper.isTainted(args[0]);
  }

  static SECOND_ARG_TAINTED_RECURSIVE(base, args, reflected) {
    return args.length > 1 && TaintHelper.risTainted(args[1]);
  }

  static LAST_ARG_TAINTED(base, args, reflected) {
    return args.length > 0 && TaintHelper.risTainted(args[args.length - 1]);
  }

  static LAST_ARG_TAINTED_RECURSIVE(base, args, reflected) {
    return args.length > 0 && TaintHelper.isTainted(args[args.length - 1]);
  }

  static NONE(base, args, reflected) {
    return false;
  }

  static ALL(base, args, reflected) {
    return true;
  }

  static validateConditionString(conditionString) {
    const validConditions = ['BASE_TAINTED', 'ANY_ARGS_TAINTED', 'FIRST_ARG_TAINTED', 'SECOND_ARG_TAINTED', 'LAST_ARG_TAINTED',
                             'BASE_TAINTED_RECURSIVE', 'ANY_ARGS_TAINTED_RECURSIVE', 'FIRST_ARG_TAINTED_RECURSIVE', 'SECOND_ARG_TAINTED_RECURSIVE',
                             'LAST_ARG_TAINTED_RECURSIVE','NONE', 'ALL'];
    const conditionTokens = conditionString.split(/\s*(&&|\|\|)\s*/);
    for (const token of conditionTokens) {
      if (!validConditions.includes(token.trim()) && !['&&', '||'].includes(token.trim())) {
        throw new Error(`Invalid condition: ${token}`);
      }
    }
  }
  
  static makeCondition(conditionString) {
    ConditionBuilder.validateConditionString(conditionString);
  
    const conditions = {
      'BASE_TAINTED_RECURSIVE': this.BASE_TAINTED_RECURSIVE,
      'ANY_ARGS_TAINTED_RECURSIVE': this.ANY_ARGS_TAINTED_RECURSIVE,
      'FIRST_ARG_TAINTED_RECURSIVE': this.FIRST_ARG_TAINTED_RECURSIVE,
      'SECOND_ARG_TAINTED_RECURSIVE': this.SECOND_ARG_TAINTED_RECURSIVE,
      'LAST_ARG_TAINTED_RECURSIVE': this.LAST_ARG_TAINTED_RECURSIVE,
      'BASE_TAINTED': this.BASE_TAINTED,
      'ANY_ARGS_TAINTED': this.ANY_ARGS_TAINTED,
      'FIRST_ARG_TAINTED': this.FIRST_ARG_TAINTED,
      'SECOND_ARG_TAINTED': this.SECOND_ARG_TAINTED,
      'LAST_ARG_TAINTED': this.LAST_ARG_TAINTED,
      'NONE': this.NONE,
      'ALL': this.ALL,
    };
  
    let modifiedConditionString = conditionString;
  
    Object.keys(conditions).forEach(key => {
      const regex = new RegExp(`\\b${key}\\b`, 'g');
      modifiedConditionString = modifiedConditionString.replace(regex, `conditions.${key}(base, args, reflected)`);
    });
  
    const conditionFunction = new Function('conditions', 'base', 'args', 'reflected', `
      return ${modifiedConditionString};
    `);
  
    return conditionFunction.bind(null, conditions);
  }
}