var url = require('url');
var request = require('request');
var parseXML = require('xml2js').parseString;
var XMLprocessors = require('xml2js/lib/processors');

/**
 * The CAS authentication types.
 * @enum {number}
 */
var AUTH_TYPE = {
    BOUNCE: 0,
    BOUNCE_REDIRECT: 1,
    BLOCK: 2
};

/**
 * @typedef {Object} CAS_options
 * @property {string}  cas_url
 * @property {string}  service_url
 * @property {('1.0'|'2.0'|'3.0')} [cas_version='3.0']
 * @property {boolean} [renew=false]
 * @property {boolean} [is_dev_mode=false]
 * @property {string}  [dev_mode_user='']
 * @property {Object}  [dev_mode_info={}]
 * @property {string}  [session_name='cas_user']
 * @property {string}  [session_info=false]
 * @property {boolean} [destroy_session=false]
 */

/**
 * validates a ticket for CAS protocol version 1.0
 *
 * @param body {string} the email body which should be parsed in order to check the ticket validation
 * @param callback {function} callback function that will be called with (err, user, userAttributes)
 */
CASAuthentication.prototype.validateTicketCas1 = function (body, callback) {
    var lines = body.split('\n');
    if (lines[0] === 'yes' && lines.length >= 2) {
        return callback(null, lines[1]);
    }
    else if (lines[0] === 'no') {
        return callback(new Error('CAS authentication failed.'));
    }
    else {
        return callback(new Error('Response from CAS server was bad.'));
    }
};


/**
 * validates a ticket for CAS protocol version 2.0 or 3.0
 *
 * @param body {string} the email body which should be parsed in order to check the ticket validation
 * @param callback {function} callback function that will be called with (err, user, userAttributes)
 */
CASAuthentication.prototype.validateTicketCas23 = function (body, callback) {
    parseXML(body, {
        trim: true,
        normalize: true,
        explicitArray: false,
        tagNameProcessors: [XMLprocessors.normalize, XMLprocessors.stripPrefix]
    }, function (err, result) {
        if (err) {
            console.info('(((((---))))))) Bad response from CAS server');
            return callback(new Error('Response from CAS server was bad.'));
        }
        //try {
        console.info('(((((---))))))) response: ' + JSON.stringify(result));
        var failure = result.serviceresponse.authenticationfailure;
        if (failure) {
            //return callback(new Error('CAS authentication failed (' + failure.$.code + ').'));
            console.info('(((((---))))))) CAS authentication failed');
            return callback({
                errorMessage: 'CAS authentication failed',
                code: failure.$.code,
                description: failure._
            });
        }
        var success = result.serviceresponse.authenticationsuccess;
        if (success) {
            return callback(null, success.user, success.attributes);
        }
        else {
            console.info('(((((---))))))) CAS authentication failed apparently');
            return callback(new Error('CAS authentication failed.'));
        }
        //}
        //catch (err) {
        //    console.info('(((((---))))))) exception when doing CAS authentication: ' + JSON.stringify(err));
        //    return callback(new Error('CAS authentication failed.'));
        //}
    });
};


/**
 * @param {CAS_options} options
 * @constructor
 */
function CASAuthentication(options) {

    if (!options || typeof options !== 'object') {
        throw new Error('CAS Authentication was not given a valid configuration object.');
    }
    if (options.cas_url === undefined) {
        throw new Error('CAS Authentication requires a cas_url parameter.');
    }
    if (options.service_url === undefined) {
        throw new Error('CAS Authentication requires a service_url parameter.');
    }

    this.cas_version = options.cas_version !== undefined ? options.cas_version : '3.0';

    if (this.cas_version === '1.0') {
        this._validateUri = '/validate';
        this._validate = this.validateTicketCas1;
    }
    else if (this.cas_version === '2.0' || this.cas_version === '3.0') {
        this._validateUri = (this.cas_version === '2.0' ? '/serviceValidate' : '/p3/serviceValidate');
        this._validate = this.validateTicketCas23;
    } else {
        throw new Error('The supplied CAS version ("' + this.cas_version + '") is not supported.');
    }

    this.cas_url = options.cas_url;
    var parsed_cas_url = url.parse(this.cas_url);
    this.cas_host = parsed_cas_url.hostname;
    this.cas_path = parsed_cas_url.pathname;

    console.info('----- CAS url: ' + this.cas_url);
    console.info('----- CAS path: ' + this.cas_path);

    this.service_url = options.service_url;

    this.renew = options.renew !== undefined ? !!options.renew : false;

    this.is_dev_mode = options.is_dev_mode !== undefined ? !!options.is_dev_mode : false;
    this.dev_mode_user = options.dev_mode_user !== undefined ? options.dev_mode_user : '';
    this.dev_mode_info = options.dev_mode_info !== undefined ? options.dev_mode_info : {};

    this.session_name = options.session_name !== undefined ? options.session_name : 'cas_user';
    this.session_info = ['2.0', '3.0'].indexOf(this.cas_version) >= 0 && options.session_info !== undefined ? options.session_info : false;
    this.destroy_session = options.destroy_session !== undefined ? !!options.destroy_session : false;

    // Bind the prototype routing methods to this instance of CASAuthentication.
    this.bounce = this.bounce.bind(this);
    this.bounce_redirect = this.bounce_redirect.bind(this);
    this.block = this.block.bind(this);
    this.logout = this.logout.bind(this);
}


/**
 * Bounces a request with CAS authentication. If the user's session is not
 * already validated with CAS, their request will be redirected to the CAS
 * login page.
 */
CASAuthentication.prototype.bounce = function (req, res, next) {

    // Handle the request with the bounce authorization type.
    this._handle(req, res, next, AUTH_TYPE.BOUNCE);
};

/**
 * Bounces a request with CAS authentication. If the user's session is not
 * already validated with CAS, their request will be redirected to the CAS
 * login page.
 */
CASAuthentication.prototype.bounce_redirect = function (req, res, next) {

    // Handle the request with the bounce authorization type.
    this._handle(req, res, next, AUTH_TYPE.BOUNCE_REDIRECT);
};

/**
 * Blocks a request with CAS authentication. If the user's session is not
 * already validated with CAS, they will receive a 401 response.
 */
CASAuthentication.prototype.block = function (req, res, next) {

    // Handle the request with the block authorization type.
    this._handle(req, res, next, AUTH_TYPE.BLOCK);
};

/**
 * Handle a request with CAS authentication.
 */
CASAuthentication.prototype._handle = function (req, res, next, authType) {

    debugger;
    // If the session has been validated with CAS, no action is required.
    if (req.session[this.session_name]) {
        // If this is a bounce redirect, redirect the authenticated user.
        if (authType === AUTH_TYPE.BOUNCE_REDIRECT) {
            if (req.query.redirectTo) {
                res.redirect(req.query.returnTo);
            } else {
                res.redirect(req.session.cas_return_to);
            }
        }
        // Otherwise, allow them through to their request.
        else {
            next();
        }
    }
    // If dev mode is active, set the CAS user to the specified dev user.
    else if (this.is_dev_mode) {
        req.session[this.session_name] = this.dev_mode_user;
        req.session[this.session_info] = this.dev_mode_info;

        // AJAX mode:
        if (req.query && req.query.returnTo) {
            res.redirect(req.query.returnTo);
            return;
        }

        // standard mode:
        next();
    }
    // If the authentication type is BLOCK, simply send a 401 response.
    else if (authType === AUTH_TYPE.BLOCK) {
        res.status(401).end();
    }
    // If there is a CAS ticket in the query string, validate it with the CAS server.
    else if (req.query && req.query.ticket) {
        this._handleTicket(req, res, next);
    }
    // Otherwise, redirect the user to the CAS login.
    else {
        this._login(req, res, next);
    }
};

/**
 * Redirects the client to the CAS login.
 */
CASAuthentication.prototype._login = function (req, res, next) {

    // Save the return URL in the session. If an explicit return URL is set as a
    // query parameter, use that. Otherwise, just use the URL from the request.
    req.session.cas_return_to = req.query.returnTo || url.parse(req.originalUrl).path;

    // Set up the query parameters.
    var query = {
        //service: req.query.returnTo || this.service_url + url.parse(req.originalUrl).pathname,
        service: this.service_url, // for AJAX
        renew: this.renew
    };

    // Redirect to the CAS login.
    res.redirect(this.cas_url + url.format({
            pathname: '/login',
            query: query
        }));
};


/**
 * Logout the currently logged in CAS user.
 */
CASAuthentication.prototype.logout = function (req, res, next) {

    // Destroy the entire session if the option is set.
    if (this.destroy_session) {
        req.session.destroy(function (err) {
            if (err) {
                console.log(err);
            }
        });
    }
    // Otherwise, just destroy the CAS session variables.
    else {
        delete req.session[this.session_name];
        if (this.session_info) {
            delete req.session[this.session_info];
        }
    }

    // Redirect the client to the CAS logout.
    res.redirect(this.cas_url + '/logout');
};


/**
 * Handles the ticket generated by the CAS login requester and validates it with the CAS login acceptor.
 *
 * @param ticket {string} the CAS service ticket to be validated
 * @param serviceUrl {string} the service URL to be used for ticket validation
 * @param callback {function} callback will be called with callback(err, user, attributes)
 *   err ... error
 *   user ... user ID
 *   attributes ... additional user attributes, if any have been returned
 */
CASAuthentication.prototype._handleTicketAjax = function (ticket, serviceUrl, callback) {
    var validateFunction;
    var requestOptions;

    console.info('+++++++++++++__+_+_+_+_+_+_+_  in cas._handleTicketAjax ...');

    validateFunction = this._validate;

    if (['1.0', '2.0', '3.0'].indexOf(this.cas_version) >= 0) {
        requestOptions = {
            uri: this.cas_url + (this.cas_version === '3.0' ? '/p3/serviceValidate' : '/serviceValidate'),
            qs: {
                service: serviceUrl,
                ticket: ticket
            }
        };
    }

    console.info('requesting: ' + JSON.stringify(requestOptions), null, 2);
    request.get(requestOptions, function (err, response, body) {
        if (err) {
            callback(err);
        }

        console.info('ticket data received: ' + body);
        validateFunction(body, function (err, user, attributes) {
            if (err) {
                callback(err);
            }
            else {
                callback(null, user, attributes);
            }
        });
    });

    console.info('end of cas._handleTicket ...');
}
;

module.exports = CASAuthentication;
