declare const auth: (allowUnauthenticated?: boolean) => (req: any, res: any, next: any) => Promise<void>;
declare function ensureScope(scope: string): (req: any, res: any, next: any) => any;
export { ensureScope };
export default auth;
