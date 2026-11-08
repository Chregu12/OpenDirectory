'use strict';
const {parseInventoryDetails}=require('../licenses/inventoryDetails');
test('keeps received-license references without coercion or actor fields',()=>{expect(parseInventoryDetails({reference:' REF-1 ',orderReference:'ORDER-1',supplier:'Vendor',receivedDate:'2026-11-02'})).toEqual({reference:'REF-1',orderReference:'ORDER-1',supplier:'Vendor',receivedDate:'2026-11-02'});expect(parseInventoryDetails(undefined)).toBeUndefined();expect(parseInventoryDetails({})).toEqual({});});
test.each([null,[],{roles:['admin']},{licenseKey:'not-accepted'},{reference:12},{reference:'x'.repeat(256)},{receivedDate:'2026-02-30'},{receivedDate:'0000-01-01'},{reference:'line\nvalue'}])('rejects invalid private inventory metadata %j',value=>{expect(()=>parseInventoryDetails(value)).toThrow();});
