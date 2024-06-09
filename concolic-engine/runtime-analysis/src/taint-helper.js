import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo } from './values/taint-info.js';


export class TaintHelper {
  static concrete(value) {
    if (value instanceof WrappedValue){
      return value.getConcrete();
    }
    return value;
  }
}
