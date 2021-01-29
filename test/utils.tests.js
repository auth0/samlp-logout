const expect = require('chai').expect;

const utils = require('../lib/utils');

describe('utils', function () {
    describe('generateUniqueID', function() {
        it('should generate an ID 20 chars long', function() {
            expect(utils.generateUniqueID().length).to.equal(20);
        });
    });
    describe('generateUniqueID', function() {
        it('should generate an ID from the alphabet', function() {
            expect('abcdef0123456789'.split('')).to.include.members(utils.generateUniqueID().split(''));
        });
    });
});