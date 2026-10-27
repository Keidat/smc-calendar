const {readFileSync}=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const source=readFileSync('static/app.js','utf8');
const handlers={};
const filter={value:'1학년 1반'};
const entries=[null];let index=0;
const context={state:{detail:false,selected:'2026-10-27',selectedEvent:null,month:new Date(2026,9,1),scope:'all'},
    dateKey:d=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`,
    $:()=>filter,innerWidth:1000,
    history:{get state(){return entries[index]},replaceState:s=>entries[index]=s,pushState:s=>{entries.splice(index+1);entries.push(s);index++}},
    window:{addEventListener:(name,fn)=>handlers[name]=fn},
    setDetailLayout:()=>{},renderCalendar:()=>{},scrollToScheduleDetails:()=>{},closeActionMenu:()=>{},showCalendar:()=>{},loadEvents:async()=>{}};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function calendarHistorySnapshot()'),source.indexOf('function setDetailLayout(')),context);
(async()=>{
    context.openComments({id:1,date:'2026-10-27'});
    context.selectScheduleDate('2026-10-28');
    context.selectScheduleDate('2026-10-28');
    assert.equal(entries.length,3,'reselecting the same date must not add history');
    await handlers.popstate({state:entries[--index]});
    assert.equal(context.state.selected,'2026-10-27');
    assert.equal(context.state.selectedEvent,1);
    assert.equal(context.state.detail,true);
    await handlers.popstate({state:entries[--index]});
    assert.equal(context.state.detail,false,'back from first detail returns to large calendar');
    await handlers.popstate({state:entries[++index]});
    assert.equal(context.state.detail,true,'forward restores detail');
    assert.equal(context.state.scope,'all');
    console.log('Calendar back/forward scenarios passed.');
})().catch(error=>{console.error(error);process.exitCode=1});
