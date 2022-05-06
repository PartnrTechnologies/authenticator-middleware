import axios, { AxiosResponse } from 'axios'
require('dotenv').config()

const AUTHENTICATOR_API_URL = process.env.AUTHENTICATOR_API_URL

const authenticateWithApiKey = async (req, res, next, apiKey) => {
	await axios
		.post(
			AUTHENTICATOR_API_URL,
			{
				api_key: apiKey,
				url: req.protocol + "://" + req.get("host") + req.originalUrl,
				origin: req.headers["CF-Connecting-IP"]
			},
		)
		.then((response: AxiosResponse) => {
			if (response.data && response.data.scopes) {
				res.locals.scopes = response.data.scopes
				return next()
			} else {
				return unavailable(
					res,
					"We weren't able to get details about your API key.",
				)
			}
		})
		.catch((error) => {
			if (error.response && error.response.data) {
				return res.json(error.response.data)
			} else {
				return unavailable(res, "We weren't able to authenticate your request.")
			}
		})
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

const authenticator = async (req, res, next) => {
	let { authorization } = req.headers
	if (
		authorization !== undefined &&
		typeof authorization === 'string' &&
		authorization.startsWith('Bearer ') &&
		authorization.split('Bearer ').length === 2
	) {
		const apiKey = authorization.split('Bearer ')[1]
		return await authenticateWithApiKey(req, res, next, apiKey)
	}
	unauthorized(res)
}

const auth = () => authenticator

function ensureScope(scope: string) {
	return (req, res, next) => {
		const userScopes = res.locals.scopes
		if (userScopes.includes(scope)) {
			return next()
		}
		return forbidden(res, 'Your API key is not valid for this request.', scope)
	}
}

export { ensureScope }

export default auth
