import {createSession,checkSession} from './sessions.js';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import {z} from 'zod';
import {parseOperation} from './schema.js';
import {createDrive} from './drive.js';
import {newUser,passwordFields,passwordMatches,publicUser} from './auth.js';
const email=z.email().max(200).transform(s=>s.toLowerCase());
const password=z.string().min(10).max(128);
const loginSchema=z.object({email,password});
export function createApp({store,secret,origins=[],driveConfig={},driveFetch=fetch}){
 if(!secret||secret.length<32)throw new Error('JWT_SECRET must be at least 32 characters');
 const app=express();app.disable('x-powered-by');app.use(helmet());app.use(cors({origin:(origin,cb)=>cb(null,!origin||origins.includes(origin))}));app.use(express.json({limit:'512kb'}));
 app.use('/api',rateLimit({windowMs:60000,limit:200}));app.get('/api/health',(_req,res)=>res.json({ok:true}));
 const authLimit=rateLimit({windowMs:15*60000,limit:30});
 const session=async(u,req)=>({token:jwt.sign({sub:u.id,v:u.tokenVersion||0,sid:await createSession(store,u,req)},secret,{expiresIn:'30d',issuer:'multi-khata'}),user:publicUser(u)});
 app.post('/api/auth/register',(_req,res)=>res.status(403).json({error:'Accounts are created by your super admin. Please contact the administrator.'}));
 app.post('/api/auth/login',authLimit,async(req,res)=>{
   const data=loginSchema.parse(req.body),user=await store.user(data.email);
   if(!await passwordMatches(data.password,user))return res.status(401).json({error:'Incorrect email or password'});
   if(user.status==='suspended')return res.status(403).json({error:'Account suspended. Please contact your administrator.'});
   res.json(await session(user,req));
 });
 const drive=createDrive({store,config:driveConfig,fetchImpl:driveFetch});app.get('/api/drive/callback',drive.callback);
 app.use('/api',async(req,res,next)=>{
   let decoded;try{decoded=jwt.verify((req.headers.authorization||'').replace(/^Bearer /,''),secret,{issuer:'multi-khata',algorithms:['HS256']});}catch{return res.status(401).json({error:'Please sign in online again. Offline entries are kept on this device.'});}
   const u=await store.userById(decoded.sub);
   if(!u||u.status==='suspended'||(u.tokenVersion||0)!==(decoded.v||0))return res.status(401).json({error:'This session was revoked or the account was suspended. Sign in again or contact your admin. Offline entries are kept.'});
   req.deviceSession=await checkSession(store,u,decoded,req,(req.headers.authorization||'').replace(/^Bearer /,''));if(!req.deviceSession)return res.status(401).json({error:'This device session was revoked. Sign in again. Offline records remain on this device.'});req.user=u;req.owner=u.id;next();
 });
 app.get('/api/auth/sessions',async(req,res)=>{const rows=await store.sessions.find({owner:req.owner,version:req.user.tokenVersion||0,revoked:false,expiresAt:{$gt:new Date()}},{projection:{_id:0,owner:0,userAgent:0,version:0}}).sort({lastActiveAt:-1}).toArray();res.json({sessions:rows.map(s=>({...s,current:s.id===req.deviceSession.id}))});});
 app.delete('/api/auth/sessions/:id',async(req,res)=>{if(req.params.id===req.deviceSession.id)return res.status(400).json({error:'Use Sign out for the current device.'});const result=await store.sessions.updateOne({id:req.params.id,owner:req.owner,revoked:false},{$set:{revoked:true}});if(!result.matchedCount)return res.status(404).json({error:'Session not found.'});res.json({ok:true});});
 app.post('/api/auth/revoke-others',async(req,res)=>{await store.sessions.updateMany({owner:req.owner,id:{$ne:req.deviceSession.id}},{$set:{revoked:true}});res.json({ok:true});});
 app.post('/api/auth/logout',async(req,res)=>{await store.sessions.updateOne({id:req.deviceSession.id,owner:req.owner},{$set:{revoked:true}});res.json({ok:true});});
 app.get('/api/auth/me',(req,res)=>res.json({user:publicUser(req.user)}));
 app.post('/api/auth/password',authLimit,async(req,res)=>{
   const data=z.object({currentPassword:password,newPassword:password}).strict().parse(req.body);
   if(!await passwordMatches(data.currentPassword,req.user))return res.status(401).json({error:'Current password is incorrect'});
   if(data.currentPassword===data.newPassword)return res.status(400).json({error:'Choose a different password'});
   const u=await store.updateUser(req.owner,{...await passwordFields(data.newPassword),mustChangePassword:false},req.user.tokenVersion||0);
   if(!u)return res.status(409).json({error:'Account changed during this request. Please sign in again.'});
   res.json(await session(u,req));
 });
 app.use('/api',(req,res,next)=>req.user.mustChangePassword?res.status(403).json({error:'Change your temporary password before continuing.',code:'PASSWORD_CHANGE_REQUIRED'}):next());
 app.use('/api/admin',(req,res,next)=>req.user.role==='superadmin'?next():res.status(403).json({error:'Super admin access required'}));
 app.get('/api/admin/accounts',async(_req,res)=>res.json({accounts:(await store.listUsers()).map(publicUser)}));
 app.post('/api/admin/accounts',async(req,res)=>{
   const data=z.object({email,password,name:z.string().trim().min(1).max(100)}).strict().parse(req.body);
   try{const user=await store.createUser(await newUser(data));res.status(201).json({user:publicUser(user)});}catch(e){if(e.code===11000)return res.status(409).json({error:'An account already uses this email address'});throw e;}
 });
 app.patch('/api/admin/accounts/:id',async(req,res)=>{
   const id=z.uuid().parse(req.params.id);const target=await store.userById(id);
   if(!target)return res.status(404).json({error:'Account not found'});
   if(target.role==='superadmin')return res.status(403).json({error:'Super admin accounts cannot be changed from this panel'});
   const data=z.object({status:z.enum(['active','suspended']).optional(),name:z.string().trim().min(1).max(100).optional(),password:password.optional()}).strict().refine(v=>Object.keys(v).length>0).parse(req.body);
   const fields={};if(data.status)fields.status=data.status;if(data.name)fields.name=data.name;if(data.password)Object.assign(fields,await passwordFields(data.password),{mustChangePassword:true});
   const updated=await store.updateUser(id,fields,target.tokenVersion||0);
   if(!updated)return res.status(409).json({error:'Account was updated elsewhere. Refresh and try again.'});
   res.json({user:publicUser(updated)});
 });
 app.get('/api/drive/status',drive.status);app.post('/api/drive/connect',drive.connect);app.delete('/api/drive/connection',drive.disconnect);app.post('/api/drive/backup',drive.backup);app.get('/api/drive/backups',drive.list);app.get('/api/drive/backups/:id',drive.download);
 app.post('/api/data/reset',async(req,res)=>{const data=z.object({confirmation:z.literal('DELETE ALL DATA'),password}).strict().parse(req.body);if(!await passwordMatches(data.password,req.user))return res.status(401).json({error:'Password is incorrect. No data was deleted.'});const user=await store.reset(req.owner,req.user.tokenVersion||0);if(!user)return res.status(409).json({error:'Account changed. Sign in and try again.'});res.json(await session(user,req));});
 // Admin provisioning does not grant access to any user's ledger.
 app.get('/api/records',async(req,res)=>res.json({records:await store.list(req.owner,req.user.dataEpoch||0),dataEpoch:req.user.dataEpoch||0}));
 app.post('/api/sync',async(req,res)=>{if((req.body.epoch??0)!==(req.user.dataEpoch||0))return res.status(409).json({error:'Account data was reset. Sign in with the updated app to refresh this device.'});const operations=z.array(z.unknown()).max(100).parse(req.body.operations).map(parseOperation);const results=[];for(const op of operations){if(!op.deleted&&(op.data.paymentMethod||['cashentry','transfer'].includes(op.kind))){const refs=[];if(op.kind==='entry')refs.push([op.data.partyId,'party']);if(op.data.bankId)refs.push([op.data.bankId,'bank']);if(op.kind==='transfer')for(const key of ['fromAccount','toAccount'])if(op.data[key]!=='cash')refs.push([op.data[key],'bank']);for(const [id,kind] of refs){const linked=await store.records.findOne({id,kind,owner:req.owner,epoch:req.user.dataEpoch||0,deleted:false});if(!linked)return res.status(400).json({error:'Transaction references an unavailable '+kind+'. Sync the account first.'});}}results.push({opId:op.opId,id:op.id,...await store.apply(req.owner,op,req.user.dataEpoch||0)});}res.json({results});});
 app.use((err,_req,res,_next)=>{if(err instanceof z.ZodError)return res.status(400).json({error:'Invalid data',details:err.issues});if(err.status===413)return res.status(413).json({error:'Request too large'});if(err.type==='entity.parse.failed')return res.status(400).json({error:'Invalid JSON'});console.error(err.message);res.status(500).json({error:'Server error. Your local changes are safe; please retry.'});});
 return app;
}
