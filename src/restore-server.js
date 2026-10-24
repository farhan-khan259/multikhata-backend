// Restore a full-server encrypted backup into a NEW EMPTY database only.
import {readFile} from 'node:fs/promises';
import {MongoClient} from 'mongodb';
import {unseal} from './crypto.js';
import {MongoStore} from './store.js';
import {z} from 'zod';
import {upgradePkrRecord} from '../../shared/legacy-pkr.js';
import {parseOperation} from './schema.js';
const file=process.argv[2];if(!file)throw new Error('Usage: node --env-file=.env src/restore-server.js BACKUP.json (empty database only)');
const key=Buffer.from(process.env.DRIVE_TOKEN_KEY||'','base64');if(key.length!==32)throw new Error('Set the original DRIVE_TOKEN_KEY for this backup.');
const envelope=JSON.parse(await readFile(file,'utf8'));if(envelope.format!=='multi-khata-server-backup-v1')throw new Error('Not a full-server backup.');
const data=JSON.parse(unseal(envelope.ciphertext,key));
z.object({users:z.array(z.object({id:z.uuid(),email:z.email(),name:z.string(),hash:z.string(),salt:z.string(),role:z.enum(['user','superadmin'])}).passthrough()),records:z.array(z.object({owner:z.uuid(),id:z.uuid(),epoch:z.number().int().nonnegative(),rev:z.number().int().positive()}).passthrough()),connections:z.array(z.object({owner:z.uuid(),refreshToken:z.string()}).passthrough())}).parse(data);
data.records=data.records.map(r=>upgradePkrRecord(r));
const owners=new Set(data.users.map(u=>u.id));if(data.users.filter(u=>u.role==='superadmin').length!==1)throw new Error('Backup must contain exactly one super admin');
for(const r of data.records){if(!owners.has(r.owner))throw new Error('Backup has an unknown owner');parseOperation({id:r.id,opId:r.lastOp,baseRev:0,kind:r.kind,data:r.data,deleted:r.deleted});}
const client=new MongoClient(process.env.MONGODB_URI||'mongodb://localhost:27017');
try{await client.connect();const db=client.db(process.env.MONGODB_DB||'multi_khata_restored');for(const name of ['users','records','drive_connections'])if(await db.collection(name).countDocuments())throw new Error('Restore refused: target database is not empty.');const store=new MongoStore(db);await store.init();const recoveryEpoch=Math.max(Date.now(),...data.users.map(u=>Math.max(u.tokenVersion||0,u.dataEpoch||0)+1));if(data.users.length)await store.users.insertMany(data.users.map(u=>({...u,tokenVersion:recoveryEpoch,dataEpoch:recoveryEpoch})));if(data.records.length)await store.records.insertMany(data.records.map(r=>({...r,epoch:recoveryEpoch})));if(data.connections.length)await store.connections.insertMany(data.connections);console.log('Server backup restored. Existing sessions are revoked; users must sign in.');}finally{await client.close();}
