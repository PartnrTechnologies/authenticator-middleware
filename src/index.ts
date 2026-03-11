import axios, { AxiosResponse } from 'axios';
import 'dotenv/config';
import jwt from "jsonwebtoken";

export enum Scope {
  COMPANIES_LIST = "@companies/list",
  COMPANIES_GET = "@companies/get",
  COMPANIES_SUMMARY_GET = "@companies/summary/get",
  COMPANIES_SECTORS_LIST = "@companies/sectors/list",
  COMPANIES_SECTORS_GET = "@companies/sectors/get",
  COMPANIES_CHARACTERISTICS_GET = "@companies/characteristics/get",
  COMPANIES_DOCUMENTS_GET = "@companies/documents/get",
  COMPANIES_RAW_REPORTS_GET = "@companies/raw-reports/get",
  COMPANIES_REPORTS_GET = "@companies/reports/get",
  COMPANIES_RATIOS_GET = "@companies/ratios/get",
  COMPANIES_RATIOS_VALUATION_GET = "@companies/ratios/valuation/get",
  COMPANIES_INSIDER_TRANSACTIONS_GET = "@companies/insider-transactions/get",
  COMPANIES_CASH_CORPORATE_ACTIONS_LIST = `@companies/cash-corporate-actions/list`,
  COMPANIES_CASH_CORPORATE_ACTIONS_GET = "@companies/cash-corporate-actions/get",
  COMPANIES_CORPORATE_ACTIONS_GET = "@companies/corporate-actions/get",
  COMPANIES_BANK_DATA_GET = "@companies/bank-data/get",
  COMPANIES_SHARES_HISTORY_GET = "@companies/shares-history/get",
  STOCKS_QUOTES_POST = "@stocks/quotes/post",
  STOCKS_QUOTE_POST = "@stocks/quote/post",
  STOCKS_VARIATIONS_GET = "@stocks/variations/get",
  STOCKS_AVERAGE_VOLUME_POST = "@stocks/average-volume/post",
  STOCKS_TICKER_QUOTE_GET = "@stocks/ticker/quote/get",
  STOCKS_TICKER_VARIATION_GET = "@stocks/ticker/variation/get",
  STOCKS_TICKER_QUOTES_GET = "@stocks/ticker/quotes/get",
  STOCKS_TICKER_AVERAGE_VOLUME_GET = "@stocks/ticker/average-volume/get",
  STOCK_QUOTE_GET_REALTIME = "@stocks/quote/get/realtime",
  QUOTES_GET = "@quotes/get",
  MACROECONOMICS_INDICATORS_LIST = "@macroeconomics/indicators/list",
  MACROECONOMICS_INDICATORS_GET = "@macroeconomics/indicators/get",
  TRADED_FUNDS_LIST = "@traded-funds/list",
  TRADED_FUNDS_GET = "@traded-funds/get",
  INVESTMENT_FIRMS_LIST = "@investment-firms/list",
  WORKFLOWS_START = "@workflows/start",
  SCREENER_RUN = "@screener/run",
  DROPS_LIST = "@drops/list",
  DROPS_WALLET_RATING_GET = "@drops/wallet-rating/get",
  DROPS_GET = "@drops/get",
  DROPS_LIKE_GET = "@drops/like/get",
  DROPS_LIKE_CREATE = "@drops/like/create",
  DROPS_LIKE_DELETE = "@drops/like/delete",
  DROPS_LOGO_GET = "@drops/logo/get",
  DROPS_RATIOS_GET = "@drops/ratios/get",
  DROPS_ACCOUNTING_RISK_RATIO_GET = "@drops/accounting-risk-ratio/get",
  DROPS_RATIO_GET = "@drops/ratio/get",
  DROPS_REFERRALS_GET = "@drops/referrals/get",
  USERS_CREATE = "@users/create",
  USERS_LIST = "@users/list",
  USERS_API_CREATE = "@users/api/create",
  USERS_NOTIFY = "@users/notify",
  USERS_ME_GET = "@users/me/get",
  USERS_ME_PATCH = "@users/me/patch",
  USERS_ME_DEVICES_CREATE = "@users/me/devices/create",
  USERS_GET = "@users/get",
  USERS_PATCH = "@users/patch",
  NEWS_GET = "@news/get",
  NEWS_LIST = "@news/list",
}

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
    Scope.MACROECONOMICS_INDICATORS_LIST,
    Scope.MACROECONOMICS_INDICATORS_GET,
    Scope.INVESTMENT_FIRMS_LIST,
    Scope.SCREENER_RUN,
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
    Scope.NEWS_GET,
    Scope.NEWS_LIST,
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
  "editor": Object.values(Scope),
  "admin": Object.values(Scope)
}

export type UserRole = "user" | "insider" | "editor" | "admin"

const AUTHENTICATOR_API_URL = process.env.AUTHENTICATOR_API_URL

const authenticateWithApiKey = async (req, res, next, apiKey, allowUnauthenticated?) => {
  await axios
    .post(
      AUTHENTICATOR_API_URL,
      {
        api_key: apiKey,
        url: req.protocol + "://" + req.get("host") + req.originalUrl,
        origin: req.headers["cf-connecting-ip"]
      },
      {
        timeout: 20000
      }
    )
    .then((response: AxiosResponse) => {
      if (response.data && response.data.scopes) {
        res.locals.scopes = response.data.scopes
        if (response.headers["request-id"]) res.set("Request-Id", response.headers["request-id"]);

        return next()
      } else {
        if (allowUnauthenticated) return next()

        return unavailable(
          res,
          "We weren't able to get details about your API key.",
        )
      }
    })
    .catch((error) => {
      if (error.response && error.response.data) {
        if (allowUnauthenticated) return next()

        return res.json(error.response.data)
      } else {
        if (allowUnauthenticated) return next()

        return unavailable(res, "We weren't able to authenticate your request.")
      }
    })
}

const authenticateWithFirebase = async (req, res, next, bearerToken, allowUnauthenticated?) => {
  await axios
    .post(
      AUTHENTICATOR_API_URL,
      {
        bearer_token: bearerToken,
        url: req.protocol + "://" + req.get("host") + req.originalUrl,
        origin: req.headers["cf-connecting-ip"]
      },
      {
        timeout: 20000
      }
    )
    .then((response: AxiosResponse) => {
      if (response.data && response.data.scopes) {
        res.locals.scopes = response.data.scopes
        res.locals.user = {
          ...response.data.user,
          auth_id: response.data.user.auth_id || response.data.user.firebase_uid,
          firebase_uid: undefined,
        }
        delete res.locals.user.firebase_uid;
        res.locals.firebase_data = response.data.firebase_data
        if (response.headers["request-id"]) res.set("Request-Id", response.headers["request-id"]);

        return next()
      } else {
        if (allowUnauthenticated) return next()

        return unavailable(
          res,
          "We weren't able to get details about you.",
        )
      }
    })
    .catch((error) => {
      if (error.response && error.response.data) {
        if (allowUnauthenticated) return next()

        return res.json(error.response.data)
      } else {
        if (allowUnauthenticated) return next()

        return unavailable(res, "We weren't able to authenticate your request.")
      }
    })
}

const generateApiKey = async (jwtData) => {
  return jwt.sign(jwtData, process.env.API_KEY_SECRET, { expiresIn: '1h' })
}

const unavailable = (res, reason?: string) => {
  res.status(503)
  res.json({
    error: {
      code: 503,
      message: `Service unavailable, please try again soon.${reason !== undefined && reason !== null ? ` ${reason}` : ''
        }`,
    },
  })
}

const unauthorized = (res, message?: string) => {
  res.status(401)
  res.json({
    error: {
      code: 401,
      message: message || 'Unauthorized.',
    },
  })
}

const forbidden = (res, message?: string, missing_scope?: string) => {
  res.status(403)
  res.json({
    error: {
      code: 403,
      message: message || 'Forbidden.',
      missing_scope,
    },
  })
}

const authenticator = async (req, res, next, allowUnauthenticated) => {
  res.locals.scopes = []

  let { authorization } = req.headers
  if (
    authorization !== undefined &&
    typeof authorization === 'string' &&
    authorization.startsWith('Bearer ') &&
    authorization.split('Bearer ').length === 2
  ) {
    const bearerToken = authorization.split('Bearer ')[1];

    const jwtData = jwt.decode(bearerToken) ?? {
      iss: ""
    };
    let issuer = jwtData["iss"];


    if (issuer !== undefined && issuer === "PARTNR LTDA") {
      return await authenticateWithApiKey(req, res, next, bearerToken, allowUnauthenticated)
    }

    if (issuer !== undefined && issuer === "https://securetoken.google.com/partnr-technologies-production") {
      return await authenticateWithFirebase(req, res, next, bearerToken, allowUnauthenticated)
    }
  }
  if (allowUnauthenticated) return next()
  unauthorized(res)
}

const auth = (allowUnauthenticated: boolean = false) => {
  return (req, res, next) => {
    return authenticator(req, res, next, allowUnauthenticated)
  }
}

function hasSpecificResourceScope(scope: Scope, userScopes: string[], params: Record<string, string>): boolean {
  const scopedPrefix = `${scope}/`
  const resourceValues = Object.values(params ?? {})
    .filter((value) => typeof value === 'string')
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value.length > 0)

  if (resourceValues.length === 0) return false

  return userScopes.some((userScope) => {
    if (!userScope.startsWith(scopedPrefix)) return false
    const scopedResources = userScope
      .slice(scopedPrefix.length)
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter((value) => value.length > 0)

    return scopedResources.some((scopedResource) => resourceValues.includes(scopedResource))
  })
}

function ensureScope(scope: Scope) {
  return (req, res, next) => {
    const userScopes = res.locals.scopes
    if (
      Array.isArray(userScopes) &&
      (userScopes.includes(scope) || hasSpecificResourceScope(scope, userScopes, req.params))
    ) {
      return next()
    }
    return forbidden(res, 'Your API key is not valid for this request.', scope)
  }
}

function ensureRole(allowedRoles: UserRole[]) {
  return (req, res, next) => {
    const user = res.locals.user
    if (user && allowedRoles.some(aR => aR === user.role)) {
      return next()
    }
    return forbidden(res, 'You do not have permission to access this resource.')
  }
}

export { ensureRole, ensureScope };

export default auth