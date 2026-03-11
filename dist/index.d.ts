import 'dotenv/config';
export declare enum Scope {
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
    COMPANIES_CASH_CORPORATE_ACTIONS_LIST = "@companies/cash-corporate-actions/list",
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
    NEWS_LIST = "@news/list"
}
export declare const USER_ROLE_SCOPES: {
    user: any[];
    insider: Scope[];
    editor: Scope[];
    admin: Scope[];
};
export type UserRole = "user" | "insider" | "editor" | "admin";
declare const auth: (allowUnauthenticated?: boolean) => (req: any, res: any, next: any) => Promise<any>;
declare function ensureScope(scope: Scope): (req: any, res: any, next: any) => any;
declare function ensureRole(allowedRoles: UserRole[]): (req: any, res: any, next: any) => any;
export { ensureRole, ensureScope };
export default auth;
