import {randomBytes,createCipheriv,createDecipheriv} from 'node:crypto';
export function seal(value,key){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);return Buffer.concat([iv,cipher.update(value),cipher.final(),cipher.getAuthTag()]).toString('base64');}
export function unseal(value,key){const b=Buffer.from(value,'base64'),dec=createDecipheriv('aes-256-gcm',key,b.subarray(0,12));dec.setAuthTag(b.subarray(-16));return Buffer.concat([dec.update(b.subarray(12,-16)),dec.final()]).toString('utf8');}
