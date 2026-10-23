import React from 'react';import '@testing-library/jest-dom';import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import CompanyGroupRulesPanel from '@/components/views/CompanyGroupRulesPanel';import {companyGroupRules} from '@/lib/companyGroupRules';import {directoryGroups} from '@/lib/directoryGroups';
jest.mock('@/lib/companyGroupRules',()=>({groupRuleAttributes:['department','title','email','username','displayName'],groupRuleOperators:['equals','startsWith','endsWith'],companyGroupRules:{get:jest.fn(),save:jest.fn(),preview:jest.fn(),sync:jest.fn(),history:jest.fn()}}));
jest.mock('@/lib/directoryGroups',()=>({directoryGroups:{get:jest.fn()}}));
const id=(n:number)=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');const group:any={id:id(3),name:'Engineering',members:[],revision:'1',createdAt:'2026-10-23T00:00:00Z'};
const page:any={actorUserId:id(1),tenantId:id(2),groupId:id(3),executionMode:'manual',rule:{groupId:id(3),tenantId:id(2),revision:'1',enabled:true,draft:{dynamic:{all:[{attribute:'department',operator:'equals',value:'Engineering'}]},childGroupIds:[],excludedUserIds:[]}}};
beforeEach(()=>{jest.clearAllMocks();(companyGroupRules.get as jest.Mock).mockResolvedValue(page);(companyGroupRules.save as jest.Mock).mockResolvedValue({rule:page.rule});(directoryGroups.get as jest.Mock).mockResolvedValue({...group,members:[id(4)],revision:'2'});});
const setup=()=>render(<CompanyGroupRulesPanel group={group} groups={[group]} actorUserId={id(1)} onChanged={jest.fn()}/>);
test('reading a rule never materializes users and changing a condition requires saving before preview',async()=>{
 setup();const preview=await screen.findByRole('button',{name:'Gespeicherte Regelvorschau prüfen'});await waitFor(()=>expect(preview).toBeEnabled());expect(companyGroupRules.sync).not.toHaveBeenCalled();
 fireEvent.change(screen.getByLabelText('Bedingungswert 1'),{target:{value:'Operations'}});expect(preview).toBeDisabled();expect(screen.getByText(/Geänderte Bedingungen zuerst speichern/)).toBeInTheDocument();
});
test('configuration and actual member reconciliation have separate explicit confirmations',async()=>{
 (companyGroupRules.preview as jest.Mock).mockResolvedValue({groupId:group.id,desired:[{userId:id(4)}],existing:[],additions:1,ruleRevision:'1'});(companyGroupRules.sync as jest.Mock).mockResolvedValue([{userId:id(4),status:'awaiting-review',code:null}]);
 setup();await waitFor(()=>expect(screen.getByRole('button',{name:'Gespeicherte Regelvorschau prüfen'})).toBeEnabled());fireEvent.change(screen.getByLabelText('Gruppenregel begründen'),{target:{value:'Actual canonical membership and review consent'}});
 fireEvent.click(screen.getByRole('button',{name:'Gespeicherte Regelvorschau prüfen'}));await screen.findByRole('button',{name:'Regelmitglieder abgleichen'});fireEvent.click(screen.getByRole('button',{name:'Regelmitglieder abgleichen'}));expect(companyGroupRules.sync).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:'Verbindlich bestätigen'}));await screen.findByText(/Unabhängige Freigabe ausstehend/);expect(companyGroupRules.save).not.toHaveBeenCalled();
});

test('preview distinguishes still stored ineffective rule links and reviewed effective manual sources',async()=>{
 (companyGroupRules.preview as jest.Mock).mockResolvedValue({groupId:group.id,desired:[],existing:[{userId:id(4),membershipId:id(8),managed:true,effective:false,validUntil:null},{userId:id(5),membershipId:id(9),managed:false,effective:true,validUntil:'2026-10-24T00:00:00.000Z'}],additions:0,ruleRevision:'1'});
 setup();await waitFor(()=>expect(screen.getByRole('button',{name:'Gespeicherte Regelvorschau prüfen'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Gespeicherte Regelvorschau prüfen'}));
 const links=await screen.findByRole('list',{name:'Wirksamkeit gespeicherter Gruppenverknüpfungen'});expect(links).toHaveTextContent(id(4)+' · Regelquelle · Unwirksam bei Prüfung');expect(links).toHaveTextContent(id(5)+' · Manuelle Quelle · Wirksam bei Prüfung · spätestens bis');expect(companyGroupRules.sync).not.toHaveBeenCalled();
});
