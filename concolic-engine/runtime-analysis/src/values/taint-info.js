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
 * b.taintInfo = a.taintInfo
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
    this.taintID = J$$.analysis.taintID++ || 0;
    this.taintSource = {
      location: iid,
      sourceLocation: undefined, // J$$.iidToLocation(iid)
      reason: reason,
      operation: operation
    }

    this.taintPropOperations = [];
    if (operation) this.taintPropOperations = [operation];
  }

  getTaintID() {
    return this.taintID;
  }

  getTaintSource() {
    return this.taintSource;
  }

  getTaintSourceReason() {
    return this.taintSource.reason;
  }

  getTaintSourceLocation() {
    return this.taintSource.location;
  }

  getTaintPropOperations() {
    return this.taintPropOperations;
  }

  addTaintPropOperation(operation, argument, location) {
    this.taintPropOperations.push(
      new TaintPropOperation(operation, argument, location));
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
   * @TODO
   * Concrete the arguments here, like toString, etc.
   * 
   * @param {String} operation 
   * @param {Array<*>} argument
   * @param {Number} location
   */
  constructor(operation, argument, location) {
    this.operation = operation;
    this.arguments = argument;
    this.location = location;
  }

  getOperation() {
    return this.operation;
  }

  getArguments() {
    return this.arguments;
  }

}

export const TaintPropName = "__TAINT__";