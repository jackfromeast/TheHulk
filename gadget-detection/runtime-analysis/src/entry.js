// JALANGI DO NOT INSTRUMENT
/**
 * @description
 * --------------------------------
 * This script is the entrypoint of the analysis script which will 
 * 1/ read the config file and apply it
 * 2/ install the analysis class to the J$.analysis  
 * 
 * @usage 
 * --------------------------------
 */

import { TaintTracking } from './taint-tracking.js'
// import { CountMostFrequentlyUsedBuiltinsAnalysis } from './others/most-frequently-used-api.js'
// import { DOMClobberingVerifier } from './others/dom-clobbering-verifier.js'

if (J$$) {
  J$$.analysis = new TaintTracking(J$$);
  // J$$.analysis = new CountMostFrequentlyUsedBuiltinsAnalysis(J$$);
  // J$$.analysis = new DOMClobberingVerifier(J$$);
} else{
  throw "[TheHulk] Analysis module cannot be installed. J$$ not found."
}


// import './taint-expose.js'