
'use strict'

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./key-did-provider-p256.cjs.production.min.js')
} else {
  module.exports = require('./key-did-provider-p256.cjs.development.js')
}
