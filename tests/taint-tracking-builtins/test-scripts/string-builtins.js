/**
 * @Name: fromCharCode-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValues = [74, 36, 49]; // Example ASCII values for 'J', '$', '1'
    taintedValues = J$$.wrapTaint(taintedValues);

    // Create a new script element
    let scriptEle = document.createElement('script');

    // Use fromCharCode to convert tainted values to a string
    let taintedSrc = String.fromCharCode.apply(null, taintedValues);
    // taintedSrc = String.fromCharCode(taintedValues[0], taintedValues[1], taintedValues[2]);
    // taintedSrc = String.fromCharCode.call(null, taintedValues[0], taintedValues[1], taintedValues[2]);
    // Set the src of the new script element
    scriptEle.src = `https://example.com/${taintedSrc}`;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: fromCharCode-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue_1 = J$$.wrapTaint(74);
    let taintedValue_2 = J$$.wrapTaint(36);
    let taintedValue_3 = J$$.wrapTaint(49);

    // Create a new script element
    let scriptEle = document.createElement('script');

    // Use fromCharCode to convert tainted values to a string
    let taintedSrc = String.fromCharCode.apply(null, [taintedValue_1, taintedValue_2, taintedValue_3]);

    // Set the src of the new script element
    scriptEle.src = `https://example.com/${taintedSrc}`;;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: at-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1example');
    let taintedChar = taintedString.at(2);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedChar}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: fromCodePoint-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedCodePoints = [74, 36, 49];
    taintedCodePoints = J$$.wrapTaint(taintedCodePoints);

    // Create a new script element
    let scriptEle = document.createElement('script');
    let taintedSrc = String.fromCodePoint.apply(null, taintedCodePoints);
    scriptEle.src = `https://example.com/${taintedSrc}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: raw-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1\\nexample');
    let taintedRaw = String.raw`${taintedString}`;

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedRaw}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: charAt-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1example');
    let taintedChar = taintedString.charAt();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedChar}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();




/**
 * @Name: charCodeAt-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1example');
    let taintedCode = taintedString.charCodeAt(2);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedCode}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: codePointAt-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1example');
    let taintedCodePoint = taintedString.codePointAt(2);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedCodePoint}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: concat-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString1 = J$$.wrapTaint('J');
    let taintedString2 = J$$.wrapTaint('$');
    let taintedString3 = J$$.wrapTaint('1');
    let taintedConcat = taintedString1.concat(taintedString2, taintedString3);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedConcat}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: endsWith-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('example$');
    let taintedEndsWith = taintedString.endsWith('$');

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedEndsWith}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: includes-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedIncludes = taintedString.includes('J$1');

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedIncludes}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: indexOf-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedIndex = taintedString.indexOf('J$1');

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedIndex}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: isWellFormed-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedWellFormed = taintedString.isWellFormed();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedWellFormed}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();



/**
 * @Name: lastIndexOf-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1example');
    let taintedLastIndex = taintedString.lastIndexOf('example');

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedLastIndex}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: localeCompare-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString1 = J$$.wrapTaint('example');
    let taintedString2 = J$$.wrapTaint('Example');
    let taintedComparison = taintedString1.localeCompare(taintedString2);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedComparison}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: match-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedMatch = taintedString.match(/J\$\d/);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedMatch}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: matchAll-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1exampleJ$2');
    let taintedMatches = Array.from(taintedString.matchAll(J$$.wrapTaint(/J\$\d/g)));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedMatches.join()}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: normalize-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedNormalized = taintedString.normalize();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedNormalized}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: padEnd-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedPadded = taintedString.padEnd(J$$.wrapTaint(10), J$$.wrapTaint('x'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedPadded}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: padStart-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedPadded = taintedString.padStart(J$$.wrapTaint(10), J$$.wrapTaint('x'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedPadded}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: repeat-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedRepeated = taintedString.repeat(J$$.wrapTaint(3));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedRepeated}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: replace-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedReplaced = taintedString.replace(J$$.wrapTaint('J$1'), J$$.wrapTaint('J$$'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedReplaced}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: replaceAll-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1exampleJ$1');
    let taintedReplaced = taintedString.replaceAll(J$$.wrapTaint('J$1'), J$$.wrapTaint('J$$'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedReplaced}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: search-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedSearchIndex = taintedString.search(J$$.wrapTaint('J$1'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedSearchIndex}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: slice-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedSlice = taintedString.slice(J$$.wrapTaint(0), J$$.wrapTaint(7));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedSlice}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: split-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1example');
    let taintedSplit = taintedString.split(J$$.wrapTaint('J$1'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedSplit.join()}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: startsWith-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1example');
    let taintedStartsWith = taintedString.startsWith(J$$.wrapTaint('J$1'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedStartsWith}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: toLocaleLowerCase-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1EXAMPLE');
    let taintedLowerCase = taintedString.toLocaleLowerCase();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedLowerCase}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: toLocaleUpperCase-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('j$1example');
    let taintedUpperCase = taintedString.toLocaleUpperCase();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedUpperCase}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: toLowerCase-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1EXAMPLE');
    let taintedLowerCase = taintedString.toLowerCase();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedLowerCase}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: toString-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1example');
    let taintedToString = taintedString.toString();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedToString}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: toUpperCase-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('j$1example');
    let taintedUpperCase = taintedString.toUpperCase();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedUpperCase}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: toWellFormed-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedWellFormed = taintedString.toWellFormed();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedWellFormed}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: trim-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('  J$1  ');
    let taintedTrim = taintedString.trim();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedTrim}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: trimEnd-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1  ');
    let taintedTrimEnd = taintedString.trimEnd();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedTrimEnd}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: trimStart-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('  J$1');
    let taintedTrimStart = taintedString.trimStart();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedTrimStart}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: valueOf-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedValue = taintedString.valueOf();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedValue}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();