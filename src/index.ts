import axios, { AxiosResponse } from 'axios'
import jwt from "jsonwebtoken";
import 'dotenv/config'

export type Scope =
	"@companies/bank-data/get" |
	"@companies/cash-dividends/get" |
	"@companies/characteristics/get" |
	"@companies/get" |
	"@companies/insider-transactions/get" |
	"@companies/list" |
	"@companies/ratios/get" |
	"@companies/ratios/valuation/get" |
	"@companies/raw-reports/get" |
	"@companies/raw-reports/reporting_models/get" |
	"@companies/reports/get" |
	"@companies/sectors/get" |
	"@companies/sectors/list" |
	"@companies/shares-history/get" |
	"@companies/stock-dividends/get" |
	"@companies/tickers/get" |
	"@macroeconomics/indicators/get" |
	"@macroeconomics/indicators/list" |
	"@stocks/quote/get" |
	"@stocks/quotes/get" |
	"@users/create" |
	"@users/notify" |
	"BOT_BROADCAST" |
	"BOT_CREATE_TOPICS" |
	"BOT_DELETE_TOPICS" |
	"BOT_GET_TOPIC" |
	"BOT_LIST_TOPICS" |
	"BOT_SEND_TO_TOPICS" |
	"BOT_UPDATE_TOPICS" |
	"COMPANIES_LIST" |
	"COMPANY_BASIC_DATA" |
	"COMPANY_DETAILS" |
	"COMPANY_FRE" |
	"COMPANY_INDICATORS" |
	"COMPANY_INSIDE_TRADES" |
	"COMPANY_RAW_REPORTS" |
	"COMPANY_REPORTS" |
	"COMPANY_SUMMARY" |
	"MACROECONOMICS";

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
		)
		.then((response: AxiosResponse) => {
			if (response.data && response.data.scopes) {
				res.locals.scopes = response.data.scopes
				res.locals.user = response.data.user
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

function ensureScope(scope: Scope) {
	return (req, res, next) => {
		const userScopes = res.locals.scopes
		if (userScopes && userScopes.includes(scope)) {
			return next()
		}
		return forbidden(res, 'Your API key is not valid for this request.', scope)
	}
}

export { ensureScope }

export default auth
