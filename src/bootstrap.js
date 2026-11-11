// Run once on your server. No default credentials and no public superadmin endpoint.
import {MongoClient} from 'mongodb';
import {z} from 'zod';
import {newUser} from './auth.js';
import {MongoStore} from './store.js';
const data=z.object({email:z.email(),password:z.string().min(10).max(128).refine(v=>v!=='choose-your-own-strong-password','Set your own SUPERADMIN_PASSWORD first'),name:z.string().min(1).max(100)}).parse({email:process.env.SUPERADMIN_EMAIL,password:process.env.SUPERADMIN_PASSWORD,name:process.env.SUPERADMIN_NAME||'Super Admin'});
const client=new MongoClient(process.env.MONGODB_URI||'mongodb://localhost:27017');
try{await client.connect();const store=new MongoStore(client.db(process.env.MONGODB_DB||'multi_khata'));await store.init();if(await store.users.findOne({role:'superadmin'}))throw new Error('A super admin already exists. Bootstrap refused.');await store.createUser(await newUser({...data,role:'superadmin',mustChangePassword:false}));console.log('Super admin created. Sign in with the email and password you configured.');}finally{await client.close();}
