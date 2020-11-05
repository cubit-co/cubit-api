'use strict'

const { v4: UUIDv4 } = require("uuid"),
    ErrorResponses = require("./constants/errorResponses"),
    SuccessResponses = require("./constants/successResponses"),
    mongoose = require('mongoose'),
    jwt = require('jsonwebtoken'),
    crypto = require('crypto-js');
const expireTime = 60 * 60 * 24 * 30;
let isConnected;
mongoose.Promise = global.Promise;
class Base {

    constructor() {
        this.event = null;
        this.context = null;
    }

    initialize(event, context) {
        context.callbackWaitsForEmptyEventLoop = false;
        this.event = event;
        this.context = context;
    }

    createErrorResponse(statusName, message = null, error = null) {
        let status;
        error = typeof error === "string" ? JSON.parse(error) : error;
        if (error && error.status && error.status.code) {
            status = Object.assign({}, error);
        } else {
            status = Object.assign({}, ErrorResponses[statusName]);
            status.status.identifier = this.extractTraceID();
            status.status.date = this.getDate();
            if (message) {
                status.status.message = message
            }
        }
        return JSON.stringify(status);
    }

    createResponse(body = null) {
        if (process.env.IS_OFFLINE) return body;
        let status = Object.assign({}, SuccessResponses["SUCCESS"]);
        status.status.identifier = this.extractTraceID();
        status.status.date = this.getDate();
        if (body) {
            status.body = body;
        }
        return status;
    }

    getDate() {
        let date = new Date();
        return date.toJSON();
    }

    createUUIDv4() {
        return UUIDv4().toString();
    }

    extractTraceID() {
        if (!this.event.headers || !this.event.headers["X-Amzn-Trace-Id"]) {
            return this.createUUIDv4();
        }
        let amzIDHeader = String(this.event.headers["X-Amzn-Trace-Id"]);
        let match = amzIDHeader.match(/^(Root=\d-)+(.*)$/);
        if (!match || !match[2]) {
            return this.createUUIDv4();
        }
        return match[2];
    }

    async connectToDatabase() {
        if (isConnected) {
            return Promise.resolve();
        }
        const db = await mongoose.connect(process.env.DB, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false });
        isConnected = db.connections[0].readyState;
    }

    convertObjectId(id) {
        return new mongoose.mongo.ObjectId(id);
    }

    getPayload(token = null) {
        let t = token ? token : this.event.headers.Authorization;
        return jwt.decode(t);
    }

    generateToken(id) {
        let expire = process.env.expireTime ? process.env.expireTime : expireTime;
        let token = { access_token: null, expire_in: expire, refresh_token: null };
        token.access_token = jwt.sign({ id: id }, process.env.secret, { expiresIn: expire });
        token.refresh_token = jwt.sign({ id: id }, process.env.secret, { expiresIn: expire * 2 });
        return token;
    }

    refreshToken(token) {
        let decode = jwt.verify(token, process.env.secret);
        return this.generateToken(decode.id);
    }

    verifyToken(token = null) {
        try {
            let t = token ? token : this.event.headers.Authorization;
            if (t == null) {
                throw this.createErrorResponse("NO_PERMISSION");
            }
            return jwt.verify(t, process.env.secret);
        } catch (error) {
            if (error.name == 'TokenExpiredError')
                throw this.createErrorResponse("NO_PERMISSION", "TOKEN EXPIRED");
            else throw this.createErrorResponse("NO_PERMISSION", null, error);
        }
    }

    decrypt(encryptedData) {
        let decryptedData = crypto.AES.decrypt(encryptedData, process.env.key);
        return JSON.parse(decryptedData.toString(crypto.enc.Utf8));
    }

    encrypt(data) {
        return crypto.AES.encrypt(JSON.stringify(data), process.env.key).toString();
    }

    encryptWithIv(data) {
        let key = '6fa979f20126cb08aa645a8f495f6d85';
        let iv = '0000000000000000';
        let cipher = crypto.AES.encrypt(JSON.stringify(data), crypto.enc.Utf8.parse(key), {
            iv: crypto.enc.Utf8.parse(iv), // parse the IV 
            padding: crypto.pad.Pkcs7,
            mode: crypto.mode.CBC
        });
        return cipher.toString();
    }
}

module.exports = Base;