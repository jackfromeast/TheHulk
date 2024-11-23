/**
 * @Name: dehydrate-object-with-type
 * @File: dehydrate-object-with-type.js
 * @Import: Yes
 * @Refer:
 *  - URL: https://canva.com/ 
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    class MyType {
      constructor() {
        this.a = 1;
        this.b = 2;
      }

      toString() {
        return "MyType";
      }
    }

    MyType.prototype.c = 3;

    let obj = new MyType();
    let obj2 = { obj:  J$$.wrapTaint(obj) };  

    let stringified = JSON.stringify(obj2);

    if (obj2.obj.c !== 3) {
      throw new Error('Error: obj.toString() !== MyType');
    }

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();