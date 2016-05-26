/*
* @Author: gbk <ck0123456@gmail.com>
* @Date:   2016-04-21 17:34:00
* @Last Modified by:   gbk
* @Last Modified time: 2016-05-23 19:40:11
*/

'use strict';

var anyproxy = require('anyproxy');

var pkg = require('../package.json');

var defaultUrl = {
  hostname: '127.0.0.1',
  port: '3000',
  path: '/'
};

// plugin defination
module.exports = {

  description: pkg.description +
    '\n  This plugin is a wrap of anyproxy.' +
    '\n  So you can find more documents here(http://anyproxy.io/)',

  options: [
    [ '    --mappings', 'simple proxy mappings' ],
    [ '-r, --rule <path>', 'path for rule file, rule will overide proxy mappings' ],
    [ '-t, --throttle <throttle>', 'throttle speed in kb/s' ],
    [ '-s, --silent', 'do not print anything into terminal' ]
  ],

  action: function(options) {
    var mappings = options.mappings;
    var rule = options.rule;
    var throttle = options.throttle;
    var silent = options.silent;

    // validate
    if (!rule && Object.prototype.toString.apply(mappings) !== '[object Object]') {
      console.log('Either rule or proxy mappings should be specified.');
      return;
    }

    // generate root ca on first time
    !anyproxy.isRootCAFileExists() && anyproxy.generateRootCA();

    // start proxy server
    new anyproxy.proxyServer({
      rule: rule ? require(rule) : {
        replaceRequestOption: parseRules(mappings),
        summary: JSON.stringify(mappings, null, '  ')
      },
      throttle: throttle,
      silent: silent,
      interceptHttps: true
    });
  }
};

// parse url
function parseUrl(url) {
  if (url === true) {
    return defaultUrl;
  }
  var t1 = url.split('//');
  var t2 = t1[1].split('/');
  var t3 = t2.shift().split(':');
  return {
    hostname: t3[0],
    port: t3[1] || '*',
    path: '/' + t2.join('/')
  };
}

// transform mapping rules to function
function parseRules(rules) {
  var body = 'try{if(0){}';
  for (var rule in rules) {
    var t1 = rule.split(' ');
    var method = t1[0];
    var ruleLoc = parseUrl(t1[1]);
    var targetLoc = parseUrl(rules[rule]);
    var filter = [];
    if (method !== '*') {
      filter.push('option.method=="' + method + '"');
    }
    if (ruleLoc.hostname.indexOf('*') !== -1) {
      var reg = ruleLoc.hostname.replace(/\./g, '\\.').replace(/\*/g, '.+');
      filter.push('/' + reg + '/.test(option.hostname)');
    } else {
      filter.push('option.hostname=="' + ruleLoc.hostname + '"');
    }
    if (ruleLoc.port !== '*') {
      filter.push('option.port==' + ruleLoc.port);
    }
    if (ruleLoc.path.indexOf('*') !== -1 || ruleLoc.path.indexOf(')') !== -1) {
      var reg = ruleLoc.path.replace(/\./g, '\\.').replace(/\//g, '\\/').replace(/\*/g, '.+');
      filter.push('/' + reg + '/.test(option.path)');
    } else {
      filter.push('option.path.indexOf("' + ruleLoc.path + '")!=-1');
    }
    body += 'else if(' + filter.join('&&') + '){option.hostname="' + targetLoc.hostname + '"';
    if (targetLoc.port !== '*') {
      body += ';option.port=' + targetLoc.port;
    }
    if (ruleLoc.path.indexOf(')') !== -1) {
      body += ';option.path=option.path.replace(/' + reg + '/,"$1")';
    }
    body += ';option.path="' + targetLoc.path + '"+option.path}\n';
  }
  body += '}catch(e){console.log(e,option)}finally{return option}';
  return new Function('req', 'option', body);
}
