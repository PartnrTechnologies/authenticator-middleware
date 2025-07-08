import 'dotenv/config';
export declare enum Scope {
    COMPANIES_LIST = "@companies/list",
    COMPANIES_GET = "@companies/get",
    COMPANIES_SUMMARY_GET = "@companies/summary/get",
    COMPANIES_SECTORS_LIST = "@companies/sectors/list",
    COMPANIES_SECTORS_GET = "@companies/sectors/get",
    COMPANIES_TICKERS_GET = "@companies/tickers/get",
    COMPANIES_CHARACTERISTICS_GET = "@companies/characteristics/get",
    COMPANIES_RAW_REPORTS_GET = "@companies/raw-reports/get",
    COMPANIES_RAW_REPORTS_REPORTING_MODELS_GET = "@companies/raw-reports/reporting_models/get",
    COMPANIES_REPORTS_GET = "@companies/reports/get",
    COMPANIES_RATIOS_GET = "@companies/ratios/get",
    COMPANIES_RATIOS_VALUATION_GET = "@companies/ratios/valuation/get",
    COMPANIES_INSIDER_TRANSACTIONS_GET = "@companies/insider-transactions/get",
    COMPANIES_STOCK_DIVIDENDS_GET = "@companies/stock-dividends/get",
    COMPANIES_CASH_DIVIDENDS_GET = "@companies/cash-dividends/get",
    COMPANIES_BANK_DATA_GET = "@companies/bank-data/get",
    STOCKS_QUOTE_GET = "@stocks/quote/get",
    STOCKS_QUOTES_GET = "@stocks/quotes/get",
    MACROECONOMICS_INDICATORS_LIST = "@macroeconomics/indicators/list",
    MACROECONOMICS_INDICATORS_GET = "@macroeconomics/indicators/get",
    COMPANIES_SHARES_HISTORY_GET = "@companies/shares-history/get",
    USERS_CREATE = "@users/create",
    USERS_NOTIFY = "@users/notify",
    NEWS_GET = "@news/get",
    NEWS_LIST = "@news/list",
    NEWS_STOCKS_LIST = "@news/stocks/list",
    NEWS_SECTORS_LIST = "@news/sectors/list",
    NEWS_CURRENCIES_LIST = "@news/currencies/list",
    NEWS_MACRO_LIST = "@news/macro/list",
    NEWS_INDEXES_LIST = "@news/indexes/list"
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
export { ensureScope, ensureRole };
export default auth;
