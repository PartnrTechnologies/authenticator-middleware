import axios from 'axios';
import 'dotenv/config';
import jwt from "jsonwebtoken";
export var Scope;
(function (Scope) {
    Scope["COMPANIES_LIST"] = "@companies/list";
    Scope["COMPANIES_GET"] = "@companies/get";
    Scope["COMPANIES_SUMMARY_GET"] = "@companies/summary/get";
    Scope["COMPANIES_SECTORS_LIST"] = "@companies/sectors/list";
    Scope["COMPANIES_SECTORS_GET"] = "@companies/sectors/get";
    Scope["COMPANIES_CHARACTERISTICS_GET"] = "@companies/characteristics/get";
    Scope["COMPANIES_DOCUMENTS_GET"] = "@companies/documents/get";
    Scope["COMPANIES_RAW_REPORTS_GET"] = "@companies/raw-reports/get";
    Scope["COMPANIES_REPORTS_GET"] = "@companies/reports/get";
    Scope["COMPANIES_RATIOS_GET"] = "@companies/ratios/get";
    Scope["COMPANIES_RATIOS_VALUATION_GET"] = "@companies/ratios/valuation/get";
    Scope["COMPANIES_INSIDER_TRANSACTIONS_GET"] = "@companies/insider-transactions/get";
    Scope["COMPANIES_CASH_CORPORATE_ACTIONS_LIST"] = "@companies/cash-corporate-actions/list";
    Scope["COMPANIES_CASH_CORPORATE_ACTIONS_GET"] = "@companies/cash-corporate-actions/get";
    Scope["COMPANIES_CORPORATE_ACTIONS_GET"] = "@companies/corporate-actions/get";
    Scope["COMPANIES_BANK_DATA_GET"] = "@companies/bank-data/get";
    Scope["COMPANIES_SHARES_HISTORY_GET"] = "@companies/shares-history/get";
    Scope["STOCKS_QUOTES_POST"] = "@stocks/quotes/post";
    Scope["STOCKS_QUOTE_POST"] = "@stocks/quote/post";
    Scope["STOCKS_VARIATIONS_GET"] = "@stocks/variations/get";
    Scope["STOCKS_AVERAGE_VOLUME_POST"] = "@stocks/average-volume/post";
    Scope["STOCKS_TICKER_QUOTE_GET"] = "@stocks/ticker/quote/get";
    Scope["STOCKS_TICKER_VARIATION_GET"] = "@stocks/ticker/variation/get";
    Scope["STOCKS_TICKER_QUOTES_GET"] = "@stocks/ticker/quotes/get";
    Scope["STOCKS_TICKER_AVERAGE_VOLUME_GET"] = "@stocks/ticker/average-volume/get";
    Scope["STOCK_QUOTE_GET_REALTIME"] = "@stocks/quote/get/realtime";
    Scope["QUOTES_GET"] = "@quotes/get";
    Scope["QUOTES_POST"] = "@quotes/post";
    Scope["QUOTES_GET_EOD"] = "@quotes/get/eod";
    Scope["QUOTES_POST_EOD"] = "@quotes/post/eod";
    Scope["QUOTES_GET_DELAY"] = "@quotes/get/delay";
    Scope["QUOTES_POST_DELAY"] = "@quotes/post/delay";
    Scope["MACROECONOMICS_INDICATORS_LIST"] = "@macroeconomics/indicators/list";
    Scope["MACROECONOMICS_INDICATORS_GET"] = "@macroeconomics/indicators/get";
    Scope["TRADED_FUNDS_LIST"] = "@traded-funds/list";
    Scope["TRADED_FUNDS_GET"] = "@traded-funds/get";
    Scope["TRADED_FUNDS_REPORTS_GET"] = "@traded-funds/reports/get";
    Scope["TRADED_FUNDS_UNITHOLDERS_GET"] = "@traded-funds/unitholders/get";
    Scope["TRADED_FUNDS_UNITHOLDERS_CONCENTRATION_GET"] = "@traded-funds/unitholders/concentration/get";
    Scope["TRADED_FUNDS_RATIOS_GET"] = "@traded-funds/ratios/get";
    Scope["TRADED_FUNDS_RATIOS_VALUATION_GET"] = "@traded-funds/ratios/valuation/get";
    Scope["TRADED_FUNDS_PORTFOLIO_GET"] = "@traded-funds/portfolio/get";
    Scope["TRADED_FUNDS_TRADES_GET"] = "@traded-funds/trades/get";
    Scope["TRADED_FUNDS_UNITS_HISTORY_GET"] = "@traded-funds/units-history/get";
    Scope["TRADED_FUNDS_GOVERNANCE_GET"] = "@traded-funds/governance/get";
    Scope["TRADED_FUNDS_CREDIT_QUALITY_GET"] = "@traded-funds/credit-quality/get";
    Scope["TRADED_FUNDS_CASH_CORPORATE_ACTIONS_GET"] = "@traded-funds/cash-corporate-actions/get";
    Scope["TRADED_FUNDS_CORPORATE_ACTIONS_GET"] = "@traded-funds/corporate-actions/get";
    Scope["INVESTMENT_FIRMS_LIST"] = "@investment-firms/list";
    Scope["WORKFLOWS_START"] = "@workflows/start";
    Scope["SCREENER_GET"] = "@screener/get";
    Scope["DROPS_LIST"] = "@drops/list";
    Scope["DROPS_WALLET_RATING_GET"] = "@drops/wallet-rating/get";
    Scope["DROPS_GET"] = "@drops/get";
    Scope["DROPS_LIKE_GET"] = "@drops/like/get";
    Scope["DROPS_LIKE_CREATE"] = "@drops/like/create";
    Scope["DROPS_LIKE_DELETE"] = "@drops/like/delete";
    Scope["DROPS_LOGO_GET"] = "@drops/logo/get";
    Scope["DROPS_RATIOS_GET"] = "@drops/ratios/get";
    Scope["DROPS_ACCOUNTING_RISK_RATIO_GET"] = "@drops/accounting-risk-ratio/get";
    Scope["DROPS_RATIO_GET"] = "@drops/ratio/get";
    Scope["DROPS_REFERRALS_GET"] = "@drops/referrals/get";
    Scope["USERS_CREATE"] = "@users/create";
    Scope["USERS_LIST"] = "@users/list";
    Scope["USERS_API_CREATE"] = "@users/api/create";
    Scope["USERS_NOTIFY"] = "@users/notify";
    Scope["USERS_ME_GET"] = "@users/me/get";
    Scope["USERS_ME_PATCH"] = "@users/me/patch";
    Scope["USERS_ME_DEVICES_CREATE"] = "@users/me/devices/create";
    Scope["USERS_GET"] = "@users/get";
    Scope["USERS_PATCH"] = "@users/patch";
    Scope["NEWS_GET"] = "@news/get";
    Scope["NEWS_LIST"] = "@news/list";
    Scope["INDEXES_GET_HIGHLIGHTS"] = "@indexes/get/highlights";
    Scope["ADMIN_FULL"] = "@admin/full";
})(Scope || (Scope = {}));
export const USER_ROLE_SCOPES = {
    "user": [],
    "insider": [
        Scope.COMPANIES_LIST,
        Scope.COMPANIES_GET,
        Scope.COMPANIES_SUMMARY_GET,
        Scope.COMPANIES_SECTORS_LIST,
        Scope.COMPANIES_SECTORS_GET,
        Scope.COMPANIES_CHARACTERISTICS_GET,
        Scope.COMPANIES_DOCUMENTS_GET,
        Scope.COMPANIES_RAW_REPORTS_GET,
        Scope.COMPANIES_REPORTS_GET,
        Scope.COMPANIES_RATIOS_GET,
        Scope.COMPANIES_RATIOS_VALUATION_GET,
        Scope.COMPANIES_INSIDER_TRANSACTIONS_GET,
        Scope.COMPANIES_CASH_CORPORATE_ACTIONS_LIST,
        Scope.COMPANIES_CASH_CORPORATE_ACTIONS_GET,
        Scope.COMPANIES_CORPORATE_ACTIONS_GET,
        Scope.COMPANIES_BANK_DATA_GET,
        Scope.STOCKS_QUOTES_POST,
        Scope.STOCKS_QUOTE_POST,
        Scope.STOCKS_VARIATIONS_GET,
        Scope.STOCKS_AVERAGE_VOLUME_POST,
        Scope.STOCKS_TICKER_QUOTE_GET,
        Scope.STOCKS_TICKER_VARIATION_GET,
        Scope.STOCKS_TICKER_QUOTES_GET,
        Scope.STOCKS_TICKER_AVERAGE_VOLUME_GET,
        Scope.QUOTES_GET,
        Scope.QUOTES_POST,
        Scope.MACROECONOMICS_INDICATORS_LIST,
        Scope.MACROECONOMICS_INDICATORS_GET,
        Scope.INVESTMENT_FIRMS_LIST,
        Scope.SCREENER_GET,
        Scope.DROPS_LIST,
        Scope.DROPS_WALLET_RATING_GET,
        Scope.DROPS_GET,
        Scope.DROPS_LIKE_GET,
        Scope.DROPS_LIKE_CREATE,
        Scope.DROPS_LIKE_DELETE,
        Scope.DROPS_LOGO_GET,
        Scope.DROPS_RATIOS_GET,
        Scope.DROPS_ACCOUNTING_RISK_RATIO_GET,
        Scope.DROPS_RATIO_GET,
        Scope.DROPS_REFERRALS_GET,
        Scope.COMPANIES_SHARES_HISTORY_GET,
        Scope.TRADED_FUNDS_LIST,
        Scope.TRADED_FUNDS_GET,
        Scope.TRADED_FUNDS_REPORTS_GET,
        Scope.TRADED_FUNDS_UNITHOLDERS_GET,
        Scope.TRADED_FUNDS_UNITHOLDERS_CONCENTRATION_GET,
        Scope.TRADED_FUNDS_RATIOS_GET,
        Scope.TRADED_FUNDS_RATIOS_VALUATION_GET,
        Scope.TRADED_FUNDS_PORTFOLIO_GET,
        Scope.TRADED_FUNDS_TRADES_GET,
        Scope.TRADED_FUNDS_UNITS_HISTORY_GET,
        Scope.TRADED_FUNDS_GOVERNANCE_GET,
        Scope.TRADED_FUNDS_CREDIT_QUALITY_GET,
        Scope.TRADED_FUNDS_CASH_CORPORATE_ACTIONS_GET,
        Scope.TRADED_FUNDS_CORPORATE_ACTIONS_GET,
        Scope.NEWS_GET,
        Scope.NEWS_LIST,
        Scope.INDEXES_GET_HIGHLIGHTS,
        Scope.USERS_LIST,
        Scope.USERS_CREATE,
        Scope.USERS_API_CREATE,
        Scope.USERS_NOTIFY,
        Scope.USERS_ME_GET,
        Scope.USERS_ME_PATCH,
        Scope.USERS_ME_DEVICES_CREATE,
        Scope.USERS_GET,
        Scope.USERS_PATCH,
        Scope.WORKFLOWS_START,
    ],
    "editor": Object.values(Scope).filter((scope) => scope !== Scope.ADMIN_FULL),
    "admin": Object.values(Scope)
};
const AUTHENTICATOR_API_URL = process.env.AUTHENTICATOR_API_URL;
const authenticateWithApiKey = async (req, res, next, apiKey, allowUnauthenticated) => {
    await axios
        .post(AUTHENTICATOR_API_URL, {
        api_key: apiKey,
        url: req.protocol + "://" + req.get("host") + req.originalUrl,
        origin: req.headers["cf-connecting-ip"]
    }, {
        timeout: 20000
    })
        .then((response) => {
        if (response.data && response.data.scopes) {
            res.locals.scopes = response.data.scopes;
            if (response.headers["request-id"])
                res.set("Request-Id", response.headers["request-id"]);
            return next();
        }
        else {
            if (allowUnauthenticated)
                return next();
            return unavailable(res, "We weren't able to get details about your API key.");
        }
    })
        .catch((error) => {
        if (error.response && error.response.data) {
            if (allowUnauthenticated)
                return next();
            return res.json(error.response.data);
        }
        else {
            if (allowUnauthenticated)
                return next();
            return unavailable(res, "We weren't able to authenticate your request.");
        }
    });
};
const authenticateWithFirebase = async (req, res, next, bearerToken, allowUnauthenticated) => {
    await axios
        .post(AUTHENTICATOR_API_URL, {
        bearer_token: bearerToken,
        url: req.protocol + "://" + req.get("host") + req.originalUrl,
        origin: req.headers["cf-connecting-ip"]
    }, {
        timeout: 20000
    })
        .then((response) => {
        if (response.data && response.data.scopes) {
            res.locals.scopes = response.data.scopes;
            res.locals.user = {
                ...response.data.user,
                auth_id: response.data.user.auth_id || response.data.user.firebase_uid,
                firebase_uid: undefined,
            };
            delete res.locals.user.firebase_uid;
            res.locals.firebase_data = response.data.firebase_data;
            if (response.headers["request-id"])
                res.set("Request-Id", response.headers["request-id"]);
            return next();
        }
        else {
            if (allowUnauthenticated)
                return next();
            return unavailable(res, "We weren't able to get details about you.");
        }
    })
        .catch((error) => {
        if (error.response && error.response.data) {
            if (allowUnauthenticated)
                return next();
            return res.json(error.response.data);
        }
        else {
            if (allowUnauthenticated)
                return next();
            return unavailable(res, "We weren't able to authenticate your request.");
        }
    });
};
const generateApiKey = async (jwtData) => {
    return jwt.sign(jwtData, process.env.API_KEY_SECRET, { expiresIn: '1h' });
};
const unavailable = (res, reason) => {
    res.status(503);
    res.json({
        error: {
            code: 503,
            message: `Service unavailable, please try again soon.${reason !== undefined && reason !== null ? ` ${reason}` : ''}`,
        },
    });
};
const unauthorized = (res, message) => {
    res.status(401);
    res.json({
        error: {
            code: 401,
            message: message || 'Unauthorized.',
        },
    });
};
const forbidden = (res, message, missing_scope) => {
    res.status(403);
    res.json({
        error: {
            code: 403,
            message: message || 'Forbidden.',
            missing_scope,
        },
    });
};
const authenticator = async (req, res, next, allowUnauthenticated) => {
    res.locals.scopes = [];
    let { authorization } = req.headers;
    if (authorization !== undefined &&
        typeof authorization === 'string' &&
        authorization.startsWith('Bearer ') &&
        authorization.split('Bearer ').length === 2) {
        const bearerToken = authorization.split('Bearer ')[1];
        const jwtData = jwt.decode(bearerToken) ?? {
            iss: ""
        };
        let issuer = jwtData["iss"];
        if (issuer !== undefined && issuer === "PARTNR LTDA") {
            return await authenticateWithApiKey(req, res, next, bearerToken, allowUnauthenticated);
        }
        if (issuer !== undefined && issuer === "https://securetoken.google.com/partnr-technologies-production") {
            return await authenticateWithFirebase(req, res, next, bearerToken, allowUnauthenticated);
        }
    }
    if (allowUnauthenticated)
        return next();
    unauthorized(res);
};
const auth = (allowUnauthenticated = false) => {
    return (req, res, next) => {
        return authenticator(req, res, next, allowUnauthenticated);
    };
};
function hasSpecificResourceScope(scope, userScopes, params) {
    const scopedPrefix = `${scope}/`;
    const resourceValues = Object.values(params ?? {})
        .filter((value) => typeof value === 'string')
        .map((value) => value.trim().toLowerCase())
        .filter((value) => value.length > 0);
    if (resourceValues.length === 0)
        return false;
    return userScopes.some((userScope) => {
        if (!userScope.startsWith(scopedPrefix))
            return false;
        const scopedResources = userScope
            .slice(scopedPrefix.length)
            .split(',')
            .map((value) => value.trim().toLowerCase())
            .filter((value) => value.length > 0);
        return scopedResources.some((scopedResource) => resourceValues.includes(scopedResource));
    });
}
function parseScopeQueryConstraints(scope, userScope) {
    const scopedPrefix = `${scope}?`;
    if (!userScope.startsWith(scopedPrefix))
        return null;
    const queryString = userScope.slice(scopedPrefix.length);
    const queryConstraints = {};
    const searchParams = new URLSearchParams(queryString);
    searchParams.forEach((value, key) => {
        const values = value
            .split(',')
            .map((item) => item.trim())
            .filter((item) => item.length > 0);
        if (values.length === 0)
            return;
        if (!queryConstraints[key])
            queryConstraints[key] = [];
        queryConstraints[key].push(...values);
    });
    return queryConstraints;
}
function getNormalizedRequestValues(value) {
    if (value === undefined || value === null)
        return [];
    const values = Array.isArray(value) ? value : [value];
    return values
        .flatMap((item) => String(item).split(','))
        .map((item) => item.trim().toLowerCase())
        .filter((item) => item.length > 0);
}
// Constraints are matched against both query string and JSON body so that GET
// routes (params in req.query) and POST routes (params in req.body) are covered.
function getNormalizedRequestParam(req, paramKey) {
    return [
        ...getNormalizedRequestValues(req.query?.[paramKey]),
        ...getNormalizedRequestValues(req.body?.[paramKey]),
    ];
}
function hasConstrainedQueryScope(scope, userScopes, req) {
    const constrainedScopes = userScopes
        .map((userScope) => parseScopeQueryConstraints(scope, userScope))
        .filter((constraints) => constraints !== null);
    if (constrainedScopes.length === 0)
        return false;
    const allowedValuesByParam = new Map();
    constrainedScopes.forEach((constraints) => {
        Object.entries(constraints).forEach(([paramKey, values]) => {
            if (!allowedValuesByParam.has(paramKey)) {
                allowedValuesByParam.set(paramKey, new Map());
            }
            const allowedValues = allowedValuesByParam.get(paramKey);
            values.forEach((value) => {
                const normalizedValue = value.toLowerCase();
                if (!allowedValues.has(normalizedValue)) {
                    allowedValues.set(normalizedValue, value);
                }
            });
        });
    });
    for (const [paramKey, allowedValues] of allowedValuesByParam.entries()) {
        const requestValues = getNormalizedRequestParam(req, paramKey);
        if (requestValues.length === 0)
            continue;
        const hasInvalidValue = requestValues.some((value) => !allowedValues.has(value));
        if (hasInvalidValue)
            return false;
    }
    for (const [paramKey, allowedValues] of allowedValuesByParam.entries()) {
        const requestValues = getNormalizedRequestParam(req, paramKey);
        if (requestValues.length > 0)
            continue;
        // Inject the fixed value so downstream handlers read it regardless of whether
        // they look in the query string (GET) or the JSON body (POST).
        const fixedValue = Array.from(allowedValues.values()).join(',');
        if (req.query)
            req.query[paramKey] = fixedValue;
        if (req.body && typeof req.body === 'object')
            req.body[paramKey] = fixedValue;
    }
    return true;
}
function ensureScope(scope) {
    return (req, res, next) => {
        const userScopes = res.locals.scopes;
        if (Array.isArray(userScopes) &&
            (userScopes.includes(scope) ||
                hasSpecificResourceScope(scope, userScopes, req.params) ||
                hasConstrainedQueryScope(scope, userScopes, req))) {
            return next();
        }
        return forbidden(res, 'Your API key is not valid for this request.', scope);
    };
}
// Quote requests are tiered by the `type` parameter (query for GET, body for POST):
//   type=current            -> "delay"  tier (delayed live/spot quote)
//   type=historical | chart -> "eod"    tier (end-of-day series), also the default
// The umbrella scope grants every tier; a tier scope grants only its own tier.
// Resource (/<ticker>) and query/body (?param=value) constraints work on every level.
function resolveQuoteType(req) {
    const raw = req.body?.type ?? req.query?.type;
    const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
    if (value === 'current' || value === 'chart')
        return value;
    return 'historical';
}
function ensureQuotesScope(umbrella, eodScope, delayScope) {
    return (req, res, next) => {
        const userScopes = res.locals.scopes;
        if (!Array.isArray(userScopes)) {
            return forbidden(res, 'Your API key is not valid for this request.', umbrella);
        }
        const tierScope = resolveQuoteType(req) === 'current' ? delayScope : eodScope;
        for (const scope of [umbrella, tierScope]) {
            if (userScopes.includes(scope) ||
                hasSpecificResourceScope(scope, userScopes, req.params) ||
                hasConstrainedQueryScope(scope, userScopes, req)) {
                return next();
            }
        }
        return forbidden(res, 'Your API key is not valid for this request.', tierScope);
    };
}
function ensureRole(allowedRoles) {
    return (req, res, next) => {
        const user = res.locals.user;
        if (user && allowedRoles.some(aR => aR === user.role)) {
            return next();
        }
        return forbidden(res, 'You do not have permission to access this resource.');
    };
}
export { ensureQuotesScope, ensureRole, ensureScope };
export default auth;
//# sourceMappingURL=index.js.map