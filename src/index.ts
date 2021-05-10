import axios from 'axios'
require('dotenv').config()

const AUTHENTICATOR_API_URL = process.env.AUTHENTICATOR_API_URL

const authenticateWithApiKey = async (req, res, next, apiKey) => {
	const response = await axios.post(
		AUTHENTICATOR_API_URL,
		{},
		{ headers: { authorization: `Bearer ${apiKey}` } },
	)
	res.locals.scopes = response.data.data.scopes
	return next()
}

const unauthorized = (res, message?: string) => {
	res.status(401)
	res.json({
		status: {
			code: 401,
			message: message || 'Unauthorized',
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
		return unauthorized(res, 'Your API key is not valid for this request.')
	}
}

export { ensureScope }

export default auth
