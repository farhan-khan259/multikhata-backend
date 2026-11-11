import {needsPkrUpgrade,upgradePkrRecord} from '../../shared/legacy-pkr.js';
// Each record is atomically compared and replaced. Deleted records remain as tombstones.
export class MongoStore {
  constructor(db){this.db=db;this.sessions=db.collection('device_sessions');this.users=db.collection('users');this.records=db.collection('records');this.connections=db.collection('drive_connections');this.oauthStates=db.collection('oauth_states');}
  async init(){await this.sessions.createIndex({id:1},{unique:true});await this.sessions.createIndex({owner:1,version:1});await this.sessions.createIndex({expiresAt:1},{expireAfterSeconds:0});await this.users.updateMany({role:{$exists:false}},{$set:{role:'user'}});await this.users.createIndex({email:1},{unique:true});await this.users.createIndex({role:1},{unique:true,partialFilterExpression:{role:'superadmin'}});await this.records.updateMany({epoch:{$exists:false}},{$set:{epoch:0}});try{await this.records.dropIndex('owner_1_id_1');}catch(e){if(e.code!==27&&e.code!==26)throw e;}await this.records.createIndex({owner:1,epoch:1,id:1},{unique:true});await this.connections.createIndex({owner:1},{unique:true});await this.oauthStates.createIndex({expiresAt:1},{expireAfterSeconds:0});await this.upgradePkr();}
  async upgradePkr(approvedAmounts={}){
    const candidates=await this.records.find({kind:{$in:['entry','bankentry','bank']},'data.currency':{$ne:'PKR'}}).toArray();
    // Validate the whole set before the first write. Immutable originals permit recovery.
    const changes=candidates.filter(needsPkrUpgrade).map(original=>({original,next:upgradePkrRecord(original,approvedAmounts)}));
    const archive=this.db.collection('pkr_upgrade_backups');
    for(const {original,next} of changes){await archive.updateOne({_id:original._id},{$setOnInsert:{original,archivedAt:new Date().toISOString(),format:'pkr-upgrade-v1'}},{upsert:true});const result=await this.records.updateOne({_id:original._id,rev:original.rev,data:original.data},{$set:{data:next.data,updatedAt:new Date().toISOString()},$inc:{rev:1},$unset:{lastOp:''}});if(result.matchedCount!==1)throw new Error('Ledger changed during PKR upgrade. Stop the server and retry.');}
    return changes.length;
  }
  async user(email){return this.users.findOne({email});}
  async userById(id){return this.users.findOne({id});}
  async listUsers(){return this.users.find({},{projection:{hash:0,salt:0,_id:0}}).sort({createdAt:-1}).toArray();}
  async updateUser(id,fields,expectedVersion){return this.users.findOneAndUpdate({id,...(expectedVersion===0?{$or:[{tokenVersion:0},{tokenVersion:{$exists:false}}]}:{tokenVersion:expectedVersion})},{$set:fields,$inc:{tokenVersion:1}},{returnDocument:'after'});}
  async createUser(user){await this.users.insertOne(user);return user;}
  async list(owner,epoch=0){return this.records.find({owner,epoch},{projection:{_id:0,owner:0,epoch:0}}).toArray();}
  async instanceSnapshot(){const users=await this.users.find({},{projection:{_id:0}}).toArray(),records=[];for(const user of users)records.push(...await this.records.find({owner:user.id,epoch:user.dataEpoch||0},{projection:{_id:0}}).toArray());const connections=await this.connections.find({},{projection:{_id:0}}).toArray();return {users,records,connections};}
  async reset(owner,version){const u=await this.users.findOneAndUpdate({id:owner,...(version===0?{$or:[{tokenVersion:0},{tokenVersion:{$exists:false}}]}:{tokenVersion:version})},{$inc:{dataEpoch:1,tokenVersion:1}},{returnDocument:'after'});if(!u)return null;await this.records.deleteMany({owner,epoch:{$lt:u.dataEpoch}});await this.db.collection('pkr_upgrade_backups').deleteMany({'original.owner':owner});await this.connections.deleteOne({owner});await this.oauthStates.deleteMany({owner});return u;}
  async apply(owner,op,epoch=0){
    let current=await this.records.findOne({owner,epoch,id:op.id});
    if(current?.lastOp===op.opId)return {status:'ok',record:clean(current)};
    if((current?.rev??0)!==op.baseRev || (current && current.kind!==op.kind))return {status:'conflict',record:current?clean(current):null};
    const next={owner,epoch,id:op.id,kind:op.kind,data:op.data,deleted:op.deleted,rev:op.baseRev+1,lastOp:op.opId,updatedAt:new Date().toISOString()};
    try{
      if(!current)await this.records.insertOne(next);
      else {const result=await this.records.replaceOne({owner,epoch,id:op.id,rev:op.baseRev},next);if(!result.modifiedCount){current=await this.records.findOne({owner,epoch,id:op.id});return {status:current?.lastOp===op.opId?'ok':'conflict',record:clean(current)};}}
    }catch(e){if(e.code!==11000)throw e;current=await this.records.findOne({owner,epoch,id:op.id});return {status:current?.lastOp===op.opId?'ok':'conflict',record:clean(current)};}
    return {status:'ok',record:clean(next)};
  }
}
function clean(record){if(!record)return null;const {_id,owner,epoch,...rest}=record;return rest;}
