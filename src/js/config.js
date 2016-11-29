/**
 * iCloud Client Configuration
 *
 * Copy this file to config.js and edit to suit your preferences.
 */
var Options = {
  // Local domain
  //
  // Which domain should ripple-client consider native?
  domain: 'local.iwallet.com',

  // Rippled to connect
  server: {
    trace: true,
    trusted: true,
    local_signing: true,

    servers: [
      //{ host: 's-west.ripple.com', port: 443, secure: true },
      { host: 'icloudcoin.org', port: 19528, secure: true }
    ],

    connection_offset: 0,
    allow_partial_history: false
  },

  // DEPRECATED: Blobvault server (old blob protocol)
  //
  // The blobvault URL for the new login protocol is set via authinfo. You can
  // still use this setting for the fallback feature.
  blobvault: 'https://icloudcoin.org:27182',

  // If set, login will persist across sessions (page reload). This is mostly
  // intended for developers, be careful about using this in a real setting.
  persistent_auth: false,

  historyApi: 'https://icloudcoin.org:27186/v1',

  // Number of transactions each page has in balance tab notifications
  transactions_per_page: 50,

  // // Configure bridges
  // bridge: {
  //   // Outbound bridges
  //   out: {
  //     // Bitcoin outbound bridge
  //     // bitcoin: 'snapswap.us'
  //     'bitcoin': 'btc2ripple.com'
  //   }
  // },

  mixpanel: {
    'token': '',
    // Don't track events by default
    'track': false
  },

  gateway: {
    host: 'isuncoins.com',
    address: 'iN8sGowQCg1qptWcJG1WyTmymKX7y9cpmr',
    fedration_url: 'https://isuncoins.com/fedration',
  },

  // production
  // activate_link: 'http://rippletrade.com/#/register/activate',
  // staging
  //activate_link: 'http://staging.ripple.com/client/#/register/activate',
  activate_link: 'https://icloudcoin.org/#/register/activate',

  // b2rAddress: 'rMwjYedjc7qqtKYVLiAccJSmCwih4LnE2q',
  // snapswapApi: 'https://snapswap.us/api/v1',

  // Number of ledgers ahead of the current ledger index where a tx is valid
  tx_last_ledger: 3,

  // Set max transaction fee for network in drops of ICC
  max_tx_network_fee: 200000,

  // Set max number of rows for orderbook
  orderbook_max_rows: 20,

  // Show transaction confirmation page
  confirmation: {
    send: true,
    exchange: true,
    trade: true
  },

  // Show advanced parameters in the trust/gateway page
  advanced_feature_switch: true,

  // Default gateway max trust amount under 'simplfied' view ie when advanced_feature_switch is false in trust/gateway page
  gateway_max_limit: 1000000000,


  currencies_all: [
    // ICC - IMPORTANT: ICC must be first entry in this list
    {value: 'ICC', name: 'iCloudCoin', custom_trade_currency_dropdown: true, standard_precision: 4, order: 5},

    // VirtualShares
    {value: 'ISC', name: 'iSunCoin', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 6},
    {value: 'IGC', name: 'iGoldenCoin', custom_trade_currency_dropdown: true, standard_precision: 4, order: 7},
    // {value: 'SCRWD', name: 'iSunCrowd Shares', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 8},
    // {value: 'SCLUD', name: 'iSunCloud Shares', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 9},
    // {value: 'DUMPG', name: 'DumplingGo Shares', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 10},
    {value: 'WCH', name: 'DplingGo Shares', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 10},

    // Fiat - Official ISO-4217
    // display used for dropdown menu
    {value: 'USD', name: 'US Dollar', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 4},
    {value: 'EUR', name: 'Euro', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 3},
    {value: 'JPY', name: 'Japanese Yen', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 0},
    {value: 'CNY', name: 'Chinese Yuan', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 0},
    {value: 'RUB', name: 'Russian Ruble', display: true, custom_trade_currency_dropdown: false, standard_precision: 2, order: 0},
    {value: 'GBP', name: 'British Pound', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 0},
    {value: 'CAD', name: 'Canadian Dollar', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 0},
    {value: 'KRW', name: 'South Korean Won', display: true, custom_trade_currency_dropdown: true, standard_precision: 2, order: 0},
    {value: 'TWD', name: 'New Taiwan Dollar', display: true, custom_trade_currency_dropdown: false, standard_precision: 2, order: 0},
    {value: 'HKD', name: 'Hong Kong Dollar', display: true, custom_trade_currency_dropdown: false, standard_precision: 2, order: 0},
    // Cryptocurrencies
    {value: 'BTC', name: 'Bitcoin', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 2},
    {value: 'LTC', name: 'Litecoin', display: true, custom_trade_currency_dropdown: true, standard_precision: 4, order: 1}
  ],

};

// store.enabled = false
// store.disable = true
// Load client-side overrides
if (store.enabled) {
  var settings = JSON.parse(store.get('ripple_settings') || '{}');


  // if (settings.bridge) {
  //   Options.bridge.out.bitcoin = settings.bridge.out.bitcoin.replace('https://www.bitstamp.net/ripple/bridge/out/bitcoin/', 'snapswap.us');
  // }

  if (settings.mixpanel) {
    Options.mixpanel = settings.mixpanel;
  }

  if (settings.max_tx_network_fee) {
    Options.max_tx_network_fee = settings.max_tx_network_fee;
  }
}
