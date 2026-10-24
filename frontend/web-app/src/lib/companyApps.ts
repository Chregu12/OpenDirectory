import {z} from 'zod';
import {api} from './api';
import {companyUuid as uuid,companyRevision as revision,CompanyWire} from './companyAssignmentProtocol';
const base='/api/clients/company';const stamp=z.string().datetime({offset:true});
const tenant=z.object({id:uuid,version:revision,generation:revision}).strict();
const client=z.object({clientId:uuid,name:z.string().min(1).max(160),enabled:z.boolean(),version:revision,purpose:z.enum(['none','company-automation']),tenant,createdAt:stamp,updatedAt:stamp,deletedAt:stamp.nullable()}).strict().refine(row=>row.deletedAt===null||!row.enabled);
const envelope={schemaVersion:z.literal(1),companyAppProtocol:z.literal(1),actorUserId:uuid,tenant};
const receipt=z.object({...envelope,client}).strict();
const credential=z.object({...envelope,client,clientSecret:z.string().regex(/^[A-Za-z0-9_-]{43}$/)}).strict();
const creation=z.object({...envelope,client,clientSecret:z.string().regex(/^[A-Za-z0-9_-]{43}$/).nullable(),created:z.boolean()}).strict().refine(row=>row.created?row.clientSecret!==null&&row.client.version==='1'&&!row.client.enabled&&row.client.deletedAt===null:row.clientSecret===null);
const page=z.object({...envelope,page:z.number().int().positive(),status:z.enum(['active','deleted']),hasMore:z.boolean(),clients:z.array(client).max(25)}).strict();
const history=z.object({...envelope,clientId:uuid,page:z.number().int().positive(),hasMore:z.boolean(),events:z.array(z.object({revision,action:z.enum(['created','updated','rotated','deleted']),actorUserId:uuid,reason:z.string().min(10).max(500),createdAt:stamp}).strict()).max(25)}).strict();
export type CompanyApp=CompanyWire<z.infer<typeof client>>;
export type CompanyAppPrincipal={actorUserId:string;tenantId:string};
export type CompanyAppHistory=CompanyWire<z.infer<typeof history>>;
export type CompanyAppInput={name:string;purpose:'none'|'company-automation';reason:string;confirm:true};
const condition=(row:CompanyApp)=>({headers:{'If-Match':`"od-client:${row.clientId}:${row.version}"`}});
function parse<S extends z.ZodType>(schema:S,value:unknown):CompanyWire<z.output<S>>{return schema.parse(value) as unknown as CompanyWire<z.output<S>>;}
function fail():never{throw new Error('Firmen-App nicht bestätigt. Originalauftrag und Registerstand prüfen; ein verlorenes Secret muss rotiert werden.');}
function checked<T extends {actorUserId:string;tenant:{id:string}}>(value:T,expected:CompanyAppPrincipal){if(value.actorUserId!==expected.actorUserId||value.tenant.id!==expected.tenantId)fail();return value;}
function target(row:CompanyApp,expected:CompanyAppPrincipal){uuid.parse(row.clientId);revision.parse(row.version);if(row.tenant.id!==expected.tenantId)fail();return base+'/'+row.clientId;}
function changed(value:CompanyApp,before:CompanyApp,expected:CompanyAppPrincipal){if(value.clientId!==before.clientId||value.tenant.id!==expected.tenantId||BigInt(value.version)!==BigInt(before.version)+BigInt(1))fail();return value;}
export const companyApps={
 async list(userId:string,number=1,status:'active'|'deleted'='active'){uuid.parse(userId);const response=await api.get(base,{params:{page:number,status}});if(response.status!==200)fail();const value=parse(page,response.data);
  if(value.actorUserId!==userId||value.page!==number||value.status!==status||value.clients.some(row=>row.tenant.id!==value.tenant.id||(row.deletedAt!==null)!==(status==='deleted'))||new Set(value.clients.map(row=>row.clientId)).size!==value.clients.length)fail();return value;
 },
 async create(input:CompanyAppInput&{requestId:string},expected:CompanyAppPrincipal){uuid.parse(input.requestId);const response=await api.post(base,input);if(response.status!==201)fail();const value=checked(parse(creation,response.data),expected);
  if(value.client.clientId!==input.requestId||value.client.tenant.id!==expected.tenantId||value.created&&(value.client.name!==input.name.trim()||value.client.purpose!==input.purpose))fail();return value;
 },
 async update(before:CompanyApp,input:CompanyAppInput&{enabled:boolean},expected:CompanyAppPrincipal){const response=await api.put(target(before,expected),input,condition(before));if(response.status!==200)fail();const value=checked(parse(receipt,response.data),expected);changed(value.client,before,expected);
  if(value.client.name!==input.name.trim()||value.client.enabled!==input.enabled||value.client.purpose!==input.purpose||value.client.deletedAt!==null)fail();return value;
 },
 async rotate(before:CompanyApp,reason:string,expected:CompanyAppPrincipal){const response=await api.post(target(before,expected)+'/rotate-secret',{reason,confirm:true},condition(before));if(response.status!==200)fail();const value=checked(parse(credential,response.data),expected);changed(value.client,before,expected);
  if(value.client.name!==before.name||value.client.purpose!==before.purpose||value.client.enabled!==before.enabled||value.client.deletedAt!==null)fail();return value;
 },
 async remove(before:CompanyApp,reason:string,expected:CompanyAppPrincipal){const response=await api.delete(target(before,expected),{...condition(before),data:{reason,confirm:true}});if(response.status!==200)fail();const value=checked(parse(receipt,response.data),expected);changed(value.client,before,expected);if(value.client.enabled||value.client.deletedAt===null)fail();return value;
 },
 async history(before:CompanyApp,expected:CompanyAppPrincipal,number=1){const response=await api.get(target(before,expected)+'/history',{params:{page:number}});if(response.status!==200)fail();const value=checked(parse(history,response.data),expected);if(value.clientId!==before.clientId||value.page!==number)fail();return value;},
};
