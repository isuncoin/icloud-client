/**
 * iCloud trading default currency pairs.
 *
 * This list is a bit arbitrary, but it's basically the Majors [1] from forex
 * trading with some ICC pairs added.
 *
 * [1] http://en.wikipedia.org/wiki/Currency_pair#The_Majors
 */

var DEFAULT_PAIRS = [
  {name: 'ICC/USD', last_used: 10}
  // {name: 'XAU (-0.5%pa)/ICC', last_used: 2},
  // {name: 'XAU (-0.5%pa)/USD', last_used: 2},
  // {name: 'BTC/ICC', last_used: 1},
  // {name: 'ICC/USD', last_used: 1},
  // {name: 'ICC/EUR', last_used: 1},
  // {name: 'ICC/JPY', last_used: 0},
  // {name: 'ICC/GBP', last_used: 0},
  // {name: 'ICC/AUD', last_used: 0},
  // {name: 'ICC/CHF', last_used: 0},
  // {name: 'ICC/CAD', last_used: 0},
  // {name: 'ICC/CNY', last_used: 0},
  // {name: 'ICC/MXN', last_used: 0},
  // {name: 'BTC/USD', last_used: 0},
  // {name: 'BTC/EUR', last_used: 0},
  // {name: 'EUR/USD', last_used: 0},
  // {name: 'USD/JPY', last_used: 0},
  // {name: 'GBP/USD', last_used: 0},
  // {name: 'AUD/USD', last_used: 0},
  // {name: 'USD/MXN', last_used: 0},
  // {name: 'USD/CHF', last_used: 0}
];

module.exports = DEFAULT_PAIRS;