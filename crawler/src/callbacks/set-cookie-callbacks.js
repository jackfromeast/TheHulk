const fs = require('fs');
const path = require('path');

module.exports = {
  setCookiesCb
};


/**
 * 
 * 
 * @param {*} visitor
 * @param {*} page
 */
async function setCookiesCb(visitor, page) {
  const cookiesRAW = visitor.config.others.COOKIE_RAW;
  const cookies = parseCookies(cookiesRAW, visitor.domain);
  await page.setCookie(...cookies);
}


/**
 * Parse the cookie string (collected) from network request headers into 
 * cookie objects.
 * 
 * E.g.
 * Cookie: _gcl_au=1.1.1061820691.1714759209; _fbp=fb.1.1714759209371.438803473; 
 *         _biz_uid=1263a2e5d3a242c9ccf36a143d0e0b0f;
 * 
 * will be parsed to:
 * [
 *   { 'name': '_gcl_au', 'value': '1.1.1061820691.1714759209' },
 *   { 'name': '_fbp', 'value': 'fb.1.1714759209371.438803473' },
 *   { 'name': '_biz_uid', 'value': '1263a2e5d3a242c9ccf36a143d0e0b0f' }
 * ]
 * 
 * @param {string} cookieString - The string containing all the cookie data
 * @returns {Array} - An array of objects, each object mapping a cookie name to its value
 */
function parseCookies(cookieString, domain) {
  const cookies = [];

  // If the cookie string starts with "Cookie: ", remove it
  cookieString = cookieString.replace(/^\s*Cookie:\s?/i, '');
  
  cookieString.split(';').forEach(cookie => {
      const parts = cookie.split('=').map(part => part.trim());
      const name = parts.shift();
      const value = parts.join('='); // Joining back parts in case the value contains '='
      cookies.push({name: name, value: value, domain: domain});
  });
  return cookies;
}


// let test = "gr_user_id=042caad9-e676-4697-86b2-5d430ade3ba0; csrftoken=fCRZFz5MchVrf13GEYvZ7tqfm57nsXx3TkAeXGBNsAePbAeeqI7d0Ex8375Ru62G; 87b5a3c3f1a55520_gr_last_sent_cs1=ByP5qDmfHz; __stripe_mid=c37306b2-e68c-44dd-b203-0d4602cf2eebf6d6c5; _gid=GA1.2.1752204449.1718741441; _gat=1; 87b5a3c3f1a55520_gr_session_id=54468aa4-a12b-44e0-a295-3d23c56740a1; 87b5a3c3f1a55520_gr_last_sent_sid_with_cs1=54468aa4-a12b-44e0-a295-3d23c56740a1; 87b5a3c3f1a55520_gr_session_id_sent_vst=54468aa4-a12b-44e0-a295-3d23c56740a1; FCNEC=%5B%5B%22AKsRol8RA5keRf4l-GT7hZNuiQdkuzf3QLH6DPP_OHqkQDWmJ6n3aocFp-2z9dCmsr9-MPseTNDNp1qVw94GlvZa3Zd0V2ShUiWUJ3d1jgdCKxoo0G3x7ke9IfnJUZYwhDa3_MeeKg9Bq40YAb68TexXiOaO8TB_wQ%3D%3D%22%5D%5D; __gads=ID=1d619e1c6451c7f1:T=1715527804:RT=1718848086:S=ALNI_Mbkc1otdxyCdbxLSN0CVC9vDJVkww; __gpi=UID=00000e14d7fa8847:T=1715527804:RT=1718848086:S=ALNI_MYGEJdJhMMLGpwXtfyLQxSpQb1BJg; __eoi=ID=fab69b6e437dbaf2:T=1715527804:RT=1718848086:S=AA-AfjacDeTQFJsjYMlfm1W6h1_W; _ga=GA1.1.907152662.1715527783; _ga_CDRWKZTDEX=GS1.1.1718848085.11.1.1718848090.55.0.0; 87b5a3c3f1a55520_gr_cs1=ByP5qDmfHz; _dd_s=rum=0&expire=1718849005589";

// console.log(parseCookies(test, 'leetcode.com'));