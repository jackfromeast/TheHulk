/**
 * @description
 * --------------------------------
 * This class is used to help maintaining the internal analysis stack
 * Specifically, the TaintTracking.stackFrames and TaintTracking.taintTransparency fields
 * 
 * Usually, the function call should starts from the user instrumented code to Jalangi2 runtime and then 
 * pass to the analysis code. However, the analysis code may necessarily call the user function again.
 * For example, the user passed value has custom toString() method, which will be implicitly called during
 * binary operation like '+'. 
 * 
 * Therefore, we need to maintain the stackFrames and monitor the recursive function calls due to the analysis code
 */
export class TaintStackHelper {
  constructor() {
    this.stackFrames = [];
    this.shouldConcretizeReturn = false;
    const MAX_STACK_SIZE = 100;
  }

  /**
   * @description
   * --------------------------------
   * This function is used to push the current stack frame into the stackFrames
   * 
   * @param {String} functionName 
   * @param {String} location 
   */
  pushStackFrame(f, iid) {
    const stackFrame = {
      function: f,
      location: iid
    };

    this.stackFrames.push(stackFrame);

    if (f === Array.prototype.filter) {
      this.shouldConcretizeReturn = true;
    }

    if (this.stackFrames.length > this.MAX_STACK_SIZE) {
      throw new Error("Maximum stack size reached caused by the analysis code.");
    }
  }

  /**
   * @description
   * --------------------------------
   * This function is used to pop the current stack frame from the stackFrames
   */
  popStackFrame() {
    let frame = this.stackFrames.pop();

    if (frame.function === Array.prototype.filter) {
      this.shouldConcretizeReturn = false;
    }

    return frame;
  }

  /**
   * @description
   * --------------------------------
   * This function is used to get the current stack frame
   */
  peakStackFrame() {
    return this.stackFrames[this.stackFrames.length - 1];
  }
}