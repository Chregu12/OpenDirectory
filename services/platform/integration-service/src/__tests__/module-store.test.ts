import { ModuleStore } from '../services/module-store';
function database(){const values=new Map();return{values,query:jest.fn(async(sql:string,args:unknown[]=[])=>{
 if(sql.startsWith('INSERT')){if(!values.has(args[0]))values.set(args[0],args[1]);return{rows:[]};}
 if(sql.startsWith('SELECT'))return{rows:[...values].map(([id,enabled])=>({id,enabled}))};
 if(sql.startsWith('UPDATE')){values.set(args[0],args[1]);return{rows:[{id:args[0],enabled:args[1]}]};}return{rows:[]};
})};}
test('a new store instance reads saved configuration rather than reseeding enabled defaults',async()=>{const db=database();const first=new ModuleStore(db);expect((await first.list())['security-suite'].enabled).toBe(true);await first.update('security-suite',false);const restarted=new ModuleStore(db);expect((await restarted.list())['security-suite'].enabled).toBe(false);});
test('failed writes are not acknowledged and initialization can recover after storage failure',async()=>{const db=database();db.query.mockRejectedValueOnce(new Error('offline'));const store=new ModuleStore(db);await expect(store.list()).rejects.toThrow('offline');expect(Object.keys(await store.list())).toHaveLength(5);db.query.mockRejectedValueOnce(new Error('offline'));await expect(store.update('security-suite',false)).rejects.toThrow('offline');});
