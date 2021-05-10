declare const auth: () => (req: any, res: any, next: any) => Promise<any>;
declare function ensureScope(scope: string): (req: any, res: any, next: any) => any;
export { ensureScope };
export default auth;
