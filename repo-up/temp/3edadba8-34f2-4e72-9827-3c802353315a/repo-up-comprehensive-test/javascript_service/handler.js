const db = require('./database');
const child_process = require('child_process');

function buildCommand() {
    // Dangerous child_process API pattern
    return child_process.exec;
}

// Long line
const description = "This is a very very very very very very very very very very very very very very very very very very very very long line";
