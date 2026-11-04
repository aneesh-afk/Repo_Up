const { doB } = require('./cycleB');
exports.doA = () => doB();
