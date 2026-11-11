import {scrypt as _scrypt,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
const scrypt=promisify(_scrypt);
export async function passwordFields(password){const salt=randomBytes(16).toString('hex');return {salt,hash:(await scrypt(password,salt,64)).toString('hex')};}
export async function passwordMatches(password,user){const actual=await scrypt(password,user?.salt||'invalid-salt',64);return !!user&&timingSafeEqual(actual,Buffer.from(user.hash,'hex'));}
export async function newUser({email,password,name,role='user',mustChangePassword=true}){return {id:randomUUID(),email:email.trim().toLowerCase(),name,role,status:'active',mustChangePassword,tokenVersion:0,createdAt:new Date().toISOString(),...await passwordFields(password)};}
export function publicUser(u){return {dataEpoch:u.dataEpoch||0,id:u.id,email:u.email,name:u.name,role:u.role||'user',status:u.status||'active',mustChangePassword:!!u.mustChangePassword,createdAt:u.createdAt||null};}
