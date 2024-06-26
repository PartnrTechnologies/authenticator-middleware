import 'dotenv/config';
export type Scope = "@companies/bank-data/get" | "@companies/cash-dividends/get" | "@companies/characteristics/get" | "@companies/get" | "@companies/insider-transactions/get" | "@companies/list" | "@companies/ratios/get" | "@companies/ratios/valuation/get" | "@companies/raw-reports/get" | "@companies/raw-reports/reporting_models/get" | "@companies/reports/get" | "@companies/sectors/get" | "@companies/sectors/list" | "@companies/shares-history/get" | "@companies/stock-dividends/get" | "@companies/tickers/get" | "@macroeconomics/indicators/get" | "@macroeconomics/indicators/list" | "@stocks/quote/get" | "@stocks/quotes/get" | "@users/create" | "@users/get" | "@users/notify" | "BOT_BROADCAST" | "BOT_CREATE_TOPICS" | "BOT_DELETE_TOPICS" | "BOT_GET_TOPIC" | "BOT_LIST_TOPICS" | "BOT_SEND_TO_TOPICS" | "BOT_UPDATE_TOPICS" | "COMPANIES_LIST" | "COMPANY_BASIC_DATA" | "COMPANY_DETAILS" | "COMPANY_FRE" | "COMPANY_INDICATORS" | "COMPANY_INSIDE_TRADES" | "COMPANY_RAW_REPORTS" | "COMPANY_REPORTS" | "COMPANY_SUMMARY" | "MACROECONOMICS";
export type UserRole = "user" | "insider" | "editor" | "admin";
declare const auth: (allowUnauthenticated?: boolean) => (req: any, res: any, next: any) => Promise<any>;
declare function ensureScope(scope: Scope): (req: any, res: any, next: any) => any;
declare function ensureRole(allowedRoles: UserRole[]): (req: any, res: any, next: any) => any;
export { ensureScope, ensureRole };
export default auth;
