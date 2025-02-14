import { WrappedValue } from "./wrapped-values.js";
import { Utils } from "../utils/util.js";
import { TaintHelper } from "../taint-helper.js";

/**
 * @description
 * --------------------------------
 * Taint information for a value.
 * This class stores the following information about a taint:
 * 1/ Taint Identifier (ID)
 * 2/ Taint Source (Location) (i.e. where the taint originated from)
 * 3/ Taint propagation operations (i.e. how the taint is being propagated)
 * 
 * The taint identifier is a unique identifier for the taint source. The derived
 * values will have the same taint identifier as value from which they are derived.
 * However, the taint propagation operations will differ.
 * 
 * The taintPropOperations is the flatted tree structure of taint propagation operations. 
 * Each taint operation constains the operation name, base, argument, location
 * and also the tainted operands (e.g. base or argument). 
 * The tainted operands save its own taintInfo, which is the parent tree of current operation node.
 * 
 * In the most cases, the taint comes from one taint source, then each node in the tree has only one parent and one child.
 * Then, we can save it in a flat array, instead of a nested object for better usability.
 * However, in some cases, the taint may come from multiple sources, then some nodes may have multiple parents, but only one child.
 * In this case, we will flat the nodes which only have one child, and keep the nodes which have multiple parents as a nested object.
 * 
 * @example
 * --------------------------------
 * let b = a.replace(/[&<>n, 0=\/]/g, "");
 * a.taintInfo = { 
 *    taintID: 1,
 *    taintSource: {
 *      location: 1,
 *      sourceLocation: undefined,
 *      reason: "DOM Clobberable Lookup",
 *      operation: "document.cookie"
 *    },
 *    taintPropOperations: []
 * }
 * 
 * b is derived from a, so we have
 * =>
 * b.taintInfo = clone(a.taintInfo)
 * b.taintInfo.addTaintPropOperation("replace", ["/[&<>n, 0=\/]/g", ""])
 */
export class TaintInfo {
  /**
   * TaintInfo constructor
   * @param {Smi} iid 
   * @param {String} reason: The reason why the taint was introduced
   * @param {TaintPropOperation} operation: The operation that introduced the taint
   */
  constructor(iid, reason, operation) {
    this.taintIDs = [J$$.analysis.taintID++ || 0];
    
    this.taintSources = [{
      location: iid,
      reason: reason,
      operation: operation
    }];

    this.addEmptyTaintSink();
    this.taintPropOperations = [];
    if (operation) this.taintPropOperations = [operation];
  }

  /**
   * @description
   * --------------------------------
   * We can create a new taintInfo by first new a empty object with prototype set to TaintInfo.prototype
   * Then we can call deriveFrom set its fields based on the taintInfos
   * 
   * If we have multiple taintInfos to derive from,
   * we have left this.taintPropOperations empty and add all the operations to the MultiTaintPropOperation
   * 
   * @param {Array<TaintInfo>} taintInfos
   */
  deriveFrom(taintInfos) {
    // this.taintIDs, this.taintSources
    for (let taintInfo of taintInfos) {
      this.addTaintSource(taintInfo.taintIDs, taintInfo.taintSources);
    }

    // this.taintSink
    this.addEmptyTaintSink();

    // this.taintPropOperations
    if (taintInfos.length > 1) {
      this.taintPropOperations = [];
    } else {
      this.taintPropOperations = this.cloneOperation(taintInfos[0].taintPropOperations);
    }

    return this;
  }

  /**
   * 
   * @param {Array<TaintPropOperation|MultiTaintPropOperation>} taintPropOperations 
   * @returns 
   */
  cloneOperation(taintPropOperations) {
    return taintPropOperations.map(op => { return this.cloneWithPrototype(op); });
  }

  cloneWithPrototype(taintPropOperation) {
    try {
      let cloned = structuredClone(taintPropOperation);
      Object.setPrototypeOf(cloned, taintPropOperation.__proto__);
      return cloned;
    } 
    catch (e) {
      J$$.analysis.logger.error("Error in cloning taintPropOperation: ", e);
      return taintPropOperation;
    }
  }

  getTaintID() {
    return this.taintIDs;
  }

  getTaintSource() {
    return this.taintSources;
  }

  getTaintSourceReason() {
    let reasons = [];
    this.taintSources.map(source => { reasons.push(source.reason); });
    reasons = Array.from(new Set(reasons));
    if ( reasons.length === 1 ) { return reasons[0]; }
    else return reasons.join(", ");
  }

  getTaintSourceLocation() {
    return this.taintSources.location;
  }

  getTaintPropOperations() {
    return this.taintPropOperations;
  }

  addEmptyTaintSink() {
    this.taintSink = {
      location: undefined,
      reason: undefined,
      operation: undefined
    }
  }

  addTaintSource(taintIds, taintSources) {
    if (!this.taintSources) {
      this.taintSources = [];
    }
    if (!this.taintIDs) {
      this.taintIDs = [];
    }
    this.taintSources.push(...taintSources);
    this.taintIDs.push(...taintIds);
  }

  /**
   * 
   * @param {*} operation 
   * @param {*} base 
   * @param {*} argument 
   * @param {*} location 
   * @param {Array<[indicator, TaintInfo]>} operandTaintInfoPairs 
   */
  addTaintPropOperation(operation, base, argument, location, operandTaintInfoPairs) {
    if (operandTaintInfoPairs.length > 1) {
      this.taintPropOperations.unshift(
        new MultiTaintPropOperation(operation, base, argument, location, operandTaintInfoPairs));
    } else {
      let indicator = operandTaintInfoPairs[0][0];
      this.taintPropOperations.unshift(
        new TaintPropOperation(operation, base, argument, location, indicator));
    }

  }

  addtaintSink(location, reason, operation) {
    this.taintSink = {
      location: location,
      reason: reason,
      operation: operation
    }
  }

  toJSON() {
    return {
      taintID: this.taintID,
      taintPropOperations: this.taintPropOperations.map(op => {
        if(op.toJSON){return op.toJSON()}else{ return op}}),
      taintSink: this.taintSink,
      taintSource: this.taintSource,
    };
  }
}

/**
 * @description
 * --------------------------------
 * Taint propagation operation. This class stores the operation that is being
 * performed on the taint.
 * 
 * @example
 * --------------------------------
 * TAINT.replace(/[&<>n, 0=\/]/g, "");
 * =>
 * new TaintPropOperation("replace", ["/[&<>n, 0=\/]/g", ""]);
 * 
 */
export class TaintPropOperation {
  /**
   * TaintPropOperation constructor
   * 
   * @param {String} operation
   * @param {*} base
   * @param {Array<*>} argument
   * @param {Number} location
   * @param {String} indicator: specify which argument is tainted or base is tainted. e.g. arg0, arg1, base
   */
  constructor(operation, base, argument, location, indicator=null) {
    this.operation = operation;
    this.base = this.cloneableOne(base);
    this.arguments = this.cloneable(argument);
    this.location = location;
    this.indicator = this.resolveIndicator(indicator);
  }

  /**
   * Determine which argument is tainted or base is tainted
   * @param {String} indicator 
   * @returns 
   */
  resolveIndicator(indicator) {
    if (indicator) {
      return indicator;
    } else {
      if (TaintHelper.isTainted(this.base)) {
        return "base";
      } else {
        for (let i = 0; i < this.arguments.length; i++) {
          if (TaintHelper.isTainted(this.arguments[i])) {
            return "arg" + i;
          }
        }
      }
    }
  }

  /**
   * Here we need to make sure that the arguments are cloneable through structuredClone
   * 
   * As far as I know, HTML elements are not cloneable
   * Therefore, we store its string representation
   * E.g. HTMLScriptElement is not cloneable and we store its HTMLScriptElement.toString()
   * 
   * Save the snapshot of the arguments and base is too slow, especially for large objects like window
   * Therefore, we only store the string representation of the base and arguments
   */
  cloneable(args) {
    return args.map(arg => {
      try {
        // If the argument itself is a TaintValue
        if (arg instanceof WrappedValue) {
          return arg.toStringInternal();
        }

        // This is very slow
        // return structuredClone(arg);
        return Utils.safeToString(arg);
      } catch (e) {
        if (arg.toString) {
          return Utils.safeToString(arg);
        }else {
          return "[Unable to clone and convert to string (no toString method)]";
        }
      }
    });
  }

  cloneableOne(base) {
    try {
      // If the argument itself is a TaintValue
      if (base instanceof WrappedValue) {
        return base.toStringInternal();
      }
      
      // This is very slow
      // return structuredClone(base);
      return Utils.safeToString(base);
    } catch (e) {
      if (base.toString) {
        return Utils.safeToString(base);
      }else {
        return "[Unable to clone and convert to string (no toString method)]";
      }
    }
  }

  /**
   * 
   * @param {Array<TaintPropOperation|MultiTaintPropOperation>} taintPropOperations 
   * @returns 
   */
  cloneOperation(taintPropOperations) {
    return taintPropOperations.map(op => { return this.cloneWithPrototype(op); });
  }

  cloneWithPrototype(taintPropOperation) {
    try {
      let cloned = structuredClone(taintPropOperation);
      Object.setPrototypeOf(cloned, taintPropOperation.__proto__);
      return cloned;
    } 
    catch (e) {
      J$$.analysis.logger.error("Error in cloning taintPropOperation: ", e);
      return taintPropOperation;
    }
  }


  getOperation() {
    return this.operation;
  }

  getArguments() {
    return this.arguments;
  }

  toJSON() {
    return {
      operation: this.operation,
      base: this.base,
      arguments: this.arguments,
      location: this.location,
      indicator: this.indicator
    };
  }
}

/**
 * @description
 * --------------------------------
 * Taint propagation operation for multiple tainted base or arguments.
 * 
 */
export class MultiTaintPropOperation extends TaintPropOperation {
  constructor(operation, base, argument, location, operandTaintInfoPairs) {
    super(operation, base, argument, location);
    this.indicators = operandTaintInfoPairs.map(([indicator, taintInfo]) => { return indicator });
    this.taintPropOperations = operandTaintInfoPairs.map(([indicator, taintInfo]) => { return this.cloneOperation(taintInfo.getTaintPropOperations()); });
  }

  toJSON() {
    return {
      operation: this.operation,
      base: this.base,
      arguments: this.arguments,
      location: this.location,
      indicator: this.indicator,
      taintPropOperations: this.taintPropOperations.map(op => {
        if(op.toJSON){return op.toJSON()}else{ return op}
      })
    };
  }
}



export const TaintPropName = "__TAINT__";
export const TaintPropNameForDebug = "__TAINT_DEBUG__";