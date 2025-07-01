// This is used in the auth guards to paypass a typescript error that happens when using the defaulf express request object in the guards
// at the line "req.tokenData"
//the error being "Property 'tokenData' does not exist on type 'Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>'.ts(2339)""
import * as express from 'express';
import { JwtPayload } from './jwtPayload';

declare module 'express' {
  export interface Request {
    tokenData?: JwtPayload;
  }
}
