import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import request from 'supertest';
import {MongoClient} from 'mongodb';
import {MongoMemoryServer} from 'mongodb-memory-server';
import {createApp} from '../src/app.js';
import {MongoStore} from '../src/store.js';
import {newUser} from '../src/auth.js';
let mongo,client,app,token,other,store,adminToken;
const auth={email:'ahmed@example.com',password:'A-test-password-123',name:'Ahmed Trading'};
const id=randomUUID();
const op=(baseRev=0,extra={})=>({id,opId:randomUUID(),baseRev,kind:'party',deleted:false,data:{name:'Ali Trading',phone:'',note:''},...extra});
const post=(body,t=token)=>request(app).post('/api/sync').set('Authorization','Bearer '+t).send(body);
before(async()=>{mongo=await MongoMemoryServer.create({instance:{args:['--nounixsocket']}});client=await MongoClient.connect(mongo.getUri());store=new MongoStore(client.db('test'));await store.init();await store.createUser(await newUser({email:'admin@example.com',password:auth.password,name:'Owner',role:'superadmin',mustChangePassword:false}));await store.createUser(await newUser({...auth,mustChangePassword:false}));await store.createUser(await newUser({...auth,email:'other@example.com',mustChangePassword:false}));app=createApp({store,secret:'test-secret-32-characters-at-least-123456789',origins:['http://localhost:5173']});let r=await request(app).post('/api/auth/login').send(auth);assert.equal(r.status,200);token=r.body.token;r=await request(app).post('/api/auth/login').send({...auth,email:'other@example.com'});other=r.body.token;r=await request(app).post('/api/auth/login').send({...auth,email:'admin@example.com'});adminToken=r.body.token;});
after(async()=>{await client?.close();await mongo?.stop()});
test('authentication rejects unauthorized requests and wrong password',async()=>{assert.equal((await request(app).get('/api/records')).status,401);assert.equal((await request(app).post('/api/auth/login').send({...auth,password:'wrong-password'})).status,401);assert.equal((await request(app).post('/api/auth/login').send(auth)).status,200);assert.equal((await request(app).post('/api/auth/register').send(auth)).status,403)});
test('operation replay is idempotent and data is isolated by account',async()=>{const o=op();let r=await post({operations:[o]});assert.equal(r.body.results[0].record.rev,1);r=await post({operations:[o]});assert.equal(r.body.results[0].record.rev,1);r=await request(app).get('/api/records').set('Authorization','Bearer '+other);assert.deepEqual(r.body.records,[]);});
test('simultaneous edits allow one writer and return the conflict',async()=>{const responses=await Promise.all([post({operations:[op(1,{data:{name:'Device A'}})]}),post({operations:[op(1,{data:{name:'Device B'}})]})]);const states=responses.map(r=>r.body.results[0].status).sort();assert.deepEqual(states,['conflict','ok']);assert.equal(responses.find(r=>r.body.results[0].status==='conflict').body.results[0].record.rev,2)});
test('deletion remains a tombstone and stale devices cannot revive it',async()=>{let r=await post({operations:[op(2,{deleted:true})]});assert.equal(r.body.results[0].record.deleted,true);r=await post({operations:[op(2)]});assert.equal(r.body.results[0].status,'conflict');assert.equal(r.body.results[0].record.deleted,true)});
test('only PKR accepted; foreign currencies, exchange rates, invalid amounts and mismatched calculations are rejected',async()=>{const data={partyId:id,currency:'PKR',direction:'given',amount:'420000.00',calculation:'10000 × 42',date:'2026-10-17',note:''};const r=await post({operations:[op(0,{id:randomUUID(),kind:'entry',data})]});assert.equal(r.status,200);assert.equal(r.body.results[0].record.data.calculation,'10000 × 42');for(const change of [{amount:'1.001'},{amount:'0'},{amount:'-5'},...['USD','USDT','RMB','AED','THB','EUR'].map(currency=>({currency})),{date:'2026-02-30'},{amount:'10'},{exchangeRate:'280'}])assert.equal((await post({operations:[op(0,{id:randomUUID(),kind:'entry',data:{...data,...change}})]})).status,400);});
test('a record cannot switch type and oversized batches fail',async()=>{let r=await post({operations:[op(3,{kind:'entry',data:{partyId:id,currency:'PKR',direction:'given',amount:'1',date:'2026-10-17',note:''}})]});assert.equal(r.body.results[0].status,'conflict');r=await post({operations:Array.from({length:101},()=>op())});assert.equal(r.status,400)});

test('two device sync engines upload offline changes, pull edits, resolve conflicts and propagate deletes',async()=>{
 await import('fake-indexeddb/auto');
 const {saveLocal,readAll,resolveConflict,pending}=await import('../../frontend/src/lib/db.js');
 const {sync}=await import('../../frontend/src/lib/sync.js');
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 const url='http://127.0.0.1:'+server.address().port;
 Object.defineProperty(globalThis,'localStorage',{configurable:true,value:{getItem:()=>url}});
 Object.defineProperty(globalThis,'navigator',{configurable:true,value:{onLine:true}});
 const a={user:{id:'device-a-cache'},token},b={user:{id:'device-b-cache'},token};
 const item={id:randomUUID(),kind:'party',data:{name:'Offline original',phone:'',note:''}};
 try{
  navigator.onLine=false;await saveLocal(a.user.id,item);await assert.rejects(()=>sync(a),/offline/);assert.equal((await pending(a.user.id)).length,1);
  navigator.onLine=true;await sync(a);await sync(b);assert.equal((await readAll(b.user.id)).find(r=>r.id===item.id).data.name,'Offline original');
  await saveLocal(a.user.id,{...item,data:{...item.data,name:'A edit'}});await saveLocal(b.user.id,{...item,data:{...item.data,name:'B edit'}});
  await sync(a);const result=await sync(b);assert.equal(result.conflicts,1);await resolveConflict(b.user.id,item.id,true);await sync(b);await sync(a);assert.equal((await readAll(a.user.id)).find(r=>r.id===item.id).data.name,'B edit');
  await saveLocal(a.user.id,{...item,data:{...item.data,name:'B edit'},deleted:true});await sync(a);await sync(b);assert.equal((await readAll(b.user.id)).find(r=>r.id===item.id).deleted,true);
 }finally{await new Promise(r=>server.close(r));}
});


test('only super admin can provision accounts; public signup and privilege injection are rejected',async()=>{
 const payload={email:'provisioned@example.com',password:auth.password,name:'HM Traders'};
 assert.equal((await request(app).post('/api/auth/register').send(payload)).status,403);
 assert.equal((await request(app).get('/api/admin/accounts').set('Authorization','Bearer '+token)).status,403);
 assert.equal((await request(app).post('/api/admin/accounts').set('Authorization','Bearer '+token).send(payload)).status,403);
 const create=await request(app).post('/api/admin/accounts').set('Authorization','Bearer '+adminToken).send(payload);assert.equal(create.status,201);assert.equal(create.body.user.role,'user');assert.equal(create.body.user.mustChangePassword,true);assert.equal(create.body.user.hash,undefined);
 assert.equal((await request(app).post('/api/admin/accounts').set('Authorization','Bearer '+adminToken).send(payload)).status,409);
 assert.equal((await request(app).post('/api/admin/accounts').set('Authorization','Bearer '+adminToken).send({...payload,email:'escalate@example.com',role:'superadmin'})).status,400);
 const accounts=await request(app).get('/api/admin/accounts').set('Authorization','Bearer '+adminToken);assert.ok(accounts.body.accounts.length>=4);assert.ok(accounts.body.accounts.every(a=>!('hash' in a)&&!('salt' in a)&&!('password' in a)));
});
test('temporary passwords must be changed; reset/suspend revoke existing sessions; reactivation preserves data',async()=>{
 const email='managed@example.com';let r=await request(app).post('/api/admin/accounts').set('Authorization','Bearer '+adminToken).send({email,password:auth.password,name:'Managed Business'});const accountId=r.body.user.id;
 r=await request(app).post('/api/auth/login').send({email,password:auth.password});let managedToken=r.body.token;
 assert.equal((await request(app).get('/api/records').set('Authorization','Bearer '+managedToken)).status,403);
 r=await request(app).post('/api/auth/password').set('Authorization','Bearer '+managedToken).send({currentPassword:auth.password,newPassword:'Personal-new-password-123'});assert.equal(r.status,200);assert.equal(r.body.user.mustChangePassword,false);const oldToken=managedToken;managedToken=r.body.token;
 assert.equal((await request(app).get('/api/records').set('Authorization','Bearer '+oldToken)).status,401);
 const item=op(0,{id:randomUUID()});assert.equal((await post({operations:[item]},managedToken)).status,200);
 r=await request(app).patch('/api/admin/accounts/'+accountId).set('Authorization','Bearer '+adminToken).send({status:'suspended'});assert.equal(r.status,200);
 assert.equal((await request(app).get('/api/records').set('Authorization','Bearer '+managedToken)).status,401);
 assert.equal((await request(app).post('/api/auth/login').send({email,password:'Personal-new-password-123'})).status,403);
 await request(app).patch('/api/admin/accounts/'+accountId).set('Authorization','Bearer '+adminToken).send({status:'active'});
 r=await request(app).post('/api/auth/login').send({email,password:'Personal-new-password-123'});managedToken=r.body.token;
 r=await request(app).get('/api/records').set('Authorization','Bearer '+managedToken);assert.equal(r.body.records[0].id,item.id);
 await request(app).patch('/api/admin/accounts/'+accountId).set('Authorization','Bearer '+adminToken).send({password:'New-temporary-password-123'});
 assert.equal((await request(app).get('/api/records').set('Authorization','Bearer '+managedToken)).status,401);
 assert.equal((await request(app).post('/api/auth/login').send({email,password:'Personal-new-password-123'})).status,401);
 r=await request(app).post('/api/auth/login').send({email,password:'New-temporary-password-123'});assert.equal(r.body.user.mustChangePassword,true);
 const owner=await store.user('admin@example.com');assert.equal((await request(app).patch('/api/admin/accounts/'+owner.id).set('Authorization','Bearer '+adminToken).send({status:'suspended'})).status,403);
});

test('bank and profile records synchronize and remain isolated',async()=>{const bankId=randomUUID();const bank=op(0,{id:bankId,kind:'bank',data:{name:'Allied Bank',currency:'PKR',label:'Business'}});let r=await post({operations:[bank]});assert.equal(r.status,200);assert.equal(r.body.results[0].status,'ok');r=await post({operations:[op(0,{id:randomUUID(),kind:'bankentry',data:{bankId,currency:'PKR',direction:'in',amount:'1000',date:'2026-10-17',note:'Deposit'}}),op(0,{id:randomUUID(),kind:'profile',data:{businessName:'HM Traders',phone:'+923001234567',countryCode:'92',whatsappTemplate:'Hi {name}: {balance}'}})]});assert.equal(r.status,200);assert.equal(r.body.results.length,2);const mine=await request(app).get('/api/records').set('Authorization','Bearer '+token),theirs=await request(app).get('/api/records').set('Authorization','Bearer '+other);assert.ok(mine.body.records.some(r=>r.id===bankId));assert.ok(!theirs.body.records.some(r=>r.id===bankId));});

test('PKR amount calculations synchronize offline create, edit and delete across devices',async()=>{
 await import('fake-indexeddb/auto');const {saveLocal,readAll}=await import('../../frontend/src/lib/db.js'),{sync}=await import('../../frontend/src/lib/sync.js');
 await store.createUser(await newUser({email:'calc@example.com',password:auth.password,name:'PKR Trader',mustChangePassword:false}));const login=await request(app).post('/api/auth/login').send({email:'calc@example.com',password:auth.password});const t=login.body.token;
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));const url='http://127.0.0.1:'+server.address().port;Object.defineProperty(globalThis,'localStorage',{configurable:true,value:{getItem:()=>url}});Object.defineProperty(globalThis,'navigator',{configurable:true,value:{onLine:true}});
 const a={user:{id:'calc-device-a'},token:t},b={user:{id:'calc-device-b'},token:t},party={id:randomUUID(),kind:'party',data:{name:'PKR Party'}},entry={id:randomUUID(),kind:'entry',data:{partyId:party.id,currency:'PKR',direction:'given',amount:'420000.00',calculation:'10000 × 42',date:'2026-10-17',note:'Calculation'}};
 try{navigator.onLine=false;await saveLocal(a.user.id,party);await saveLocal(a.user.id,entry);await assert.rejects(()=>sync(a),/offline/);navigator.onLine=true;await sync(a);await sync(b);let remote=(await readAll(b.user.id)).find(r=>r.id===entry.id);assert.equal(remote.data.calculation,'10000 × 42');assert.equal(remote.data.amount,'420000.00');await saveLocal(b.user.id,{...remote,data:{...remote.data,amount:'400000.00',calculation:'10000 × 40'}});await sync(b);await sync(a);remote=(await readAll(a.user.id)).find(r=>r.id===entry.id);assert.equal(remote.data.amount,'400000.00');await saveLocal(a.user.id,{...remote,deleted:true});await sync(a);await sync(b);assert.equal((await readAll(b.user.id)).find(r=>r.id===entry.id).deleted,true);}finally{await new Promise(r=>server.close(r));}
});

test('Drive connect uses single-use state/PKCE and encrypted refresh tokens; backup and restore are account-scoped',async()=>{
 let uploaded;const files=new Map();
 const fakeFetch=async(url,options={})=>{url=String(url);if(url.includes('oauth2.googleapis.com/revoke'))return new Response('{}');if(url.includes('oauth2.googleapis.com/token')){const p=new URLSearchParams(options.body);if(p.get('grant_type')==='authorization_code'){assert.ok(p.get('code_verifier'));return Response.json({refresh_token:'private-google-refresh-token',access_token:'initial-access'});}assert.equal(p.get('refresh_token'),'private-google-refresh-token');return Response.json({access_token:'access-token'});}if(url.includes('uploadType=resumable'))return new Response('',{headers:{location:'https://www.googleapis.com/upload/drive/v3/files?upload_id=test'}});if(options.method==='PUT'){uploaded=JSON.parse(options.body);return Response.json({id:'backup-file',name:'Backup.json',createdTime:new Date().toISOString()});}if(url.endsWith('/drive/v3/files')&&options.method==='POST')return Response.json({id:'folder-id'});if(url.includes('alt=media'))return Response.json(uploaded);if(url.includes('/backup-file?fields='))return Response.json({appProperties:{account:authId,format:'multi-khata-backup-v2'},size:'1000'});if(url.includes('/other-file?fields='))return Response.json({appProperties:{account:'not-this-user',format:'multi-khata-backup-v2'},size:'100'});if(url.includes('/drive/v3/files?')&&new URL(url).searchParams.get('q')?.includes("mimeType = 'application/vnd.google-apps.folder'"))return Response.json({files:[]});if(url.includes('/drive/v3/files?'))return Response.json({files:[{id:'backup-file',name:'Backup.json',createdTime:new Date().toISOString()}]});throw Error('Unexpected fake Google request '+url);};
 const authId=(await store.user(auth.email)).id;
 const driveApp=createApp({store,secret:'test-secret-32-characters-at-least-123456789',driveConfig:{clientId:'test-client',clientSecret:'test-secret',redirectUri:'https://khata.example.com/api/drive/callback',tokenKey:Buffer.alloc(32,1).toString('base64')},driveFetch:fakeFetch});
 const authorize=req=>req.set('Authorization','Bearer '+token);
 let r=await authorize(request(driveApp).post('/api/drive/connect')).send({});assert.equal(r.status,200);const url=new URL(r.body.url);assert.equal(url.searchParams.get('scope'),'https://www.googleapis.com/auth/drive.file');assert.equal(url.searchParams.get('code_challenge_method'),'S256');const state=url.searchParams.get('state');
 r=await request(driveApp).get('/api/drive/callback?state=invalid&code=x');assert.equal(r.status,400);
 r=await request(driveApp).get('/api/drive/callback').query({state,code:'test-code'});assert.equal(r.status,200);
 assert.equal((await request(driveApp).get('/api/drive/callback').query({state,code:'test-code'})).status,400);
 const c=await store.connections.findOne({owner:authId});assert.notEqual(c.refreshToken,'private-google-refresh-token');assert.ok(!JSON.stringify(c).includes('private-google-refresh-token'));
 r=await authorize(request(driveApp).get('/api/drive/status'));assert.equal(r.body.connected,true);assert.equal(r.body.refreshToken,undefined);
 r=await authorize(request(driveApp).post('/api/drive/backup')).send({epoch:0});assert.equal(r.status,200);assert.equal(uploaded.format,'multi-khata-backup-v2');assert.ok(uploaded.records.some(r=>r.kind==='bank'));assert.ok(!JSON.stringify(uploaded).includes('"hash"'));assert.ok(uploaded.records.every(r=>!r.owner));
 r=await authorize(request(driveApp).get('/api/drive/backups'));assert.equal(r.body.backups[0].id,'backup-file');
 r=await authorize(request(driveApp).get('/api/drive/backups/backup-file'));assert.equal(r.body.snapshot.format,'multi-khata-backup-v2');
 assert.equal((await authorize(request(driveApp).get('/api/drive/backups/other-file'))).status,403);
 await authorize(request(driveApp).delete('/api/drive/connection'));r=await authorize(request(driveApp).get('/api/drive/status'));assert.equal(r.body.connected,false);
 assert.equal((await request(app).post('/api/drive/connect').set('Authorization','Bearer '+token).send({})).status,503);
});

test('delete-all requires password and exact confirmation; reset isolates old writes and preserves other accounts',async()=>{
 const otherOwner=(await store.user('other@example.com')).id,own=(await store.user(auth.email)).id;
 const otherRecord=op(0,{id:randomUUID()});await store.apply(otherOwner,otherRecord);const count=(await store.list(own)).length;assert.ok(count>0);
 let r=await request(app).post('/api/data/reset').set('Authorization','Bearer '+token).send({confirmation:'DELETE ALL DATA',password:'incorrect-password'});assert.equal(r.status,401);assert.equal((await store.list(own)).length,count);
 r=await request(app).post('/api/data/reset').set('Authorization','Bearer '+token).send({confirmation:'DELETE',password:auth.password});assert.equal(r.status,400);
 r=await request(app).post('/api/data/reset').set('Authorization','Bearer '+token).send({confirmation:'DELETE ALL DATA',password:auth.password});assert.equal(r.status,200);assert.equal(r.body.user.dataEpoch,1);const newToken=r.body.token;
 assert.equal((await request(app).get('/api/records').set('Authorization','Bearer '+token)).status,401);
 let fresh=await request(app).get('/api/records').set('Authorization','Bearer '+newToken);assert.deepEqual(fresh.body.records,[]);
 assert.equal((await post({operations:[op(0,{id:randomUUID()})],epoch:0},newToken)).status,409);
 // An old in-flight write uses the obsolete epoch and can never appear in the fresh ledger.
 await store.apply(own,op(0,{id:randomUUID()}),0);fresh=await request(app).get('/api/records').set('Authorization','Bearer '+newToken);assert.deepEqual(fresh.body.records,[]);
 assert.ok((await store.list(otherOwner)).some(r=>r.id===otherRecord.id));assert.equal((await store.user(auth.email)).status,'active');
});

test('super admin full-server backups encrypt all account data and omit obsolete reset epochs',async()=>{
 const {seal,unseal}=await import('../src/crypto.js');const owner=await store.user('admin@example.com'),key=Buffer.alloc(32,2);await store.connections.updateOne({owner:owner.id},{$set:{refreshToken:seal('owner-refresh',key),folderId:'owner-folder'}},{upsert:true});let uploaded;
 const fakeFetch=async(url,options={})=>{if(String(url).includes('/token'))return Response.json({access_token:'owner-access'});if(String(url).includes('uploadType=resumable')){assert.equal(JSON.parse(options.body).appProperties.format,'multi-khata-server-backup-v1');return new Response('',{headers:{location:'https://www.googleapis.com/upload/drive/v3/files?upload_id=owner'}});}if(options.method==='PUT'){uploaded=JSON.parse(options.body);return Response.json({id:'owner-backup',name:'Server.json'});}throw Error('Unexpected mock request')};
 const app2=createApp({store,secret:'test-secret-32-characters-at-least-123456789',driveConfig:{clientId:'id',clientSecret:'secret',redirectUri:'https://example.com/api/drive/callback',tokenKey:key.toString('base64')},driveFetch:fakeFetch});
 const r=await request(app2).post('/api/drive/backup').set('Authorization','Bearer '+adminToken).send({epoch:0});assert.equal(r.status,200);assert.equal(uploaded.encrypted,true);assert.equal(uploaded.format,'multi-khata-server-backup-v1');assert.ok(!JSON.stringify(uploaded).includes('"hash"'));const snapshot=JSON.parse(unseal(uploaded.ciphertext,key));assert.ok(snapshot.users.length>=4);assert.ok(snapshot.users.some(u=>u.role==='superadmin'&&u.hash));for(const row of snapshot.records){const u=snapshot.users.find(u=>u.id===row.owner);assert.equal(row.epoch,u.dataEpoch||0);}
});

test('encrypted full-server recovery succeeds only in an empty database and revokes restored sessions',async()=>{
 const {seal}=await import('../src/crypto.js'),{mkdtemp,writeFile,rm}=await import('node:fs/promises'),{tmpdir}=await import('node:os'),{join}=await import('node:path'),{execFile}=await import('node:child_process'),{promisify}=await import('node:util');const run=promisify(execFile),folder=await mkdtemp(join(tmpdir(),'khata-recovery-')),file=join(folder,'server.json'),key=Buffer.alloc(32,2),snapshot=await store.instanceSnapshot();await writeFile(file,JSON.stringify({format:'multi-khata-server-backup-v1',encrypted:true,ciphertext:seal(JSON.stringify(snapshot),key)}));const env={...process.env,MONGODB_URI:mongo.getUri(),MONGODB_DB:'recovery_test',DRIVE_TOKEN_KEY:key.toString('base64')};
 try{await run(process.execPath,[new URL('../src/restore-server.js',import.meta.url).pathname,file],{env,timeout:15000});const restored=client.db('recovery_test');assert.equal(await restored.collection('users').countDocuments(),snapshot.users.length);assert.equal(await restored.collection('records').countDocuments(),snapshot.records.length);const owner=snapshot.users.find(u=>u.role==='superadmin');const restoredOwner=await restored.collection('users').findOne({id:owner.id});assert.ok(restoredOwner.tokenVersion>(owner.tokenVersion||0));assert.ok(restoredOwner.dataEpoch>(owner.dataEpoch||0));assert.ok((await restored.collection('records').findOne({})).epoch>0);await assert.rejects(()=>run(process.execPath,[new URL('../src/restore-server.js',import.meta.url).pathname,file],{env,timeout:15000}),/not empty/);}finally{await rm(folder,{recursive:true,force:true})}
});

test('offline PKR receipts settle PKR debt on both devices and edits/deletes recalculate the balance',async()=>{
 await import('fake-indexeddb/auto');
 const {saveLocal,readAll}=await import('../../frontend/src/lib/db.js'),{sync}=await import('../../frontend/src/lib/sync.js'),{partySettlement}=await import('../../frontend/src/lib/settlement.js');
 await store.createUser(await newUser({email:'pkr-settlement@example.com',password:auth.password,name:'PKR Settlement',mustChangePassword:false}));
 const login=await request(app).post('/api/auth/login').send({email:'pkr-settlement@example.com',password:auth.password}),t=login.body.token;
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));const url='http://127.0.0.1:'+server.address().port;
 Object.defineProperty(globalThis,'localStorage',{configurable:true,value:{getItem:()=>url}});Object.defineProperty(globalThis,'navigator',{configurable:true,value:{onLine:true}});
 const a={user:{id:'pkr-settle-a'},token:t},b={user:{id:'pkr-settle-b'},token:t},party={id:randomUUID(),kind:'party',data:{name:'Settlement Party'}},debit={id:randomUUID(),kind:'entry',data:{partyId:party.id,currency:'PKR',direction:'given',amount:'280000',date:'2026-10-01',note:'Original USDT'}},credit={id:randomUUID(),kind:'entry',data:{partyId:party.id,currency:'PKR',direction:'received',amount:'140000',date:'2026-10-02',note:'PKR received'}};
 try{
  navigator.onLine=false;await saveLocal(a.user.id,party);await saveLocal(a.user.id,debit);navigator.onLine=true;await sync(a);await sync(b);
  navigator.onLine=false;await saveLocal(b.user.id,credit);assert.equal(partySettlement(await readAll(b.user.id),party.id).netPKR,14000000n);navigator.onLine=true;await sync(b);await sync(a);assert.equal(partySettlement(await readAll(a.user.id),party.id).netPKR,14000000n);
  await saveLocal(b.user.id,{...credit,data:{...credit.data,amount:'280000'}});await sync(b);await sync(a);assert.equal(partySettlement(await readAll(a.user.id),party.id).netPKR,0n);
  const paid=(await readAll(b.user.id)).find(r=>r.id===credit.id);await saveLocal(b.user.id,{...paid,deleted:true});await sync(b);await sync(a);assert.equal(partySettlement(await readAll(a.user.id),party.id).netPKR,28000000n);assert.equal((await readAll(a.user.id)).find(r=>r.id===debit.id).data.currency,'PKR');
 }finally{await new Promise(r=>server.close(r));}
});


test('Mongo PKR upgrade archives original rows, keeps IDs, advances revisions and rejects stale writes',async()=>{const db=client.db('upgrade-test'),migrationStore=new MongoStore(db),owner=randomUUID(),partyId=randomUUID(),bankId=randomUUID(),entryId=randomUUID();await migrationStore.init();const rows=[{owner,epoch:0,id:bankId,kind:'bank',rev:2,lastOp:randomUUID(),deleted:false,data:{name:'Old bank',currency:'USDT',label:''}},{owner,epoch:0,id:entryId,kind:'entry',rev:3,lastOp:randomUUID(),deleted:false,data:{partyId,bankId,currency:'USDT',exchangeRate:'280',amount:'100',direction:'given',date:'2026-10-17',note:'Original note'}}];await migrationStore.records.insertMany(rows);assert.equal(await migrationStore.upgradePkr(),2);const result=await migrationStore.list(owner);const e=result.find(r=>r.id===entryId);assert.equal(e.data.amount,'28000.00');assert.equal(e.data.currency,'PKR');assert.equal(e.data.bankId,bankId);assert.equal(e.data.note,'Original note');assert.equal(e.rev,4);assert.equal(e.lastOp,undefined);const archived=await db.collection('pkr_upgrade_backups').findOne({'original.id':entryId});assert.equal(archived.original.data.currency,'USDT');assert.equal(archived.original.data.amount,'100');assert.equal(await migrationStore.upgradePkr(),0);const stale=await migrationStore.apply(owner,{id:entryId,opId:randomUUID(),baseRev:3,kind:'entry',deleted:false,data:e.data});assert.equal(stale.status,'conflict');await migrationStore.users.insertOne({id:owner,email:'reset-migration@example.com',role:'user',tokenVersion:0,dataEpoch:0});await migrationStore.reset(owner,0);assert.equal(await db.collection('pkr_upgrade_backups').countDocuments({'original.owner':owner}),0);});

test('Mongo PKR upgrade preflight refuses unknown rates without partially migrating or inventing money',async()=>{const db=client.db('upgrade-missing'),s=new MongoStore(db);await s.init();const owner=randomUUID(),partyId=randomUUID(),a=randomUUID(),b=randomUUID();await s.records.insertMany([a,b].map((id,i)=>({owner,epoch:0,id,kind:'entry',rev:1,deleted:false,data:{partyId,currency:'USDT',exchangeRate:i?null:'280',amount:'100',direction:'given',date:'2026-10-17',note:''}})));await assert.rejects(()=>s.upgradePkr(),/approved PKR amount/);assert.ok((await s.list(owner)).every(r=>r.data.currency==='USDT'));assert.equal(await db.collection('pkr_upgrade_backups').countDocuments(),0);assert.equal(await s.upgradePkr({[b]:'28000.00'}),2);assert.ok((await s.list(owner)).every(r=>r.data.currency==='PKR'));});
