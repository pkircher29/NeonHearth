const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createRequire}=require('node:module');
const {resolve}=require('node:path');
const requireUi=createRequire(resolve(__dirname,'../../apps/desktop/package.json'));
const merge=requireUi('deepmerge');

test('an own __proto__ key in the target cannot poison the returned object',()=>{
  const target=JSON.parse('{"__proto__":{"admin":true},"safe":{"value":1}}');
  const result=merge(target,{safe:{other:2}});
  assert.equal(Object.getPrototypeOf(result),Object.prototype);
  assert.equal(result.admin,undefined);
  assert.equal({}.admin,undefined);
  assert.deepEqual(result.safe,{value:1,other:2});
});

test('null-prototype source keys stay data without changing the result prototype',()=>{
  const source=Object.assign(Object.create(null),JSON.parse('{"__proto__":{"admin":true},"safe":1}'));
  const result=merge(Object.create(null),source);
  assert.equal(Object.getPrototypeOf(result),Object.prototype);
  assert.equal(result.admin,undefined);
  assert.equal(result.safe,1);
});

test('Svelte config merges retain custom arrays, symbols and source isolation',()=>{
  const key=Symbol('config');
  const first={compilerOptions:{dev:false},extensions:['.svelte'],[key]:{before:true}};
  const second={compilerOptions:{runes:true},extensions:['.svx'],[key]:{after:true}};
  const result=merge(first,second,{arrayMerge:(_target,source)=>source});
  assert.deepEqual(result.extensions,['.svx']);
  assert.deepEqual(result.compilerOptions,{dev:false,runes:true});
  assert.deepEqual(result[key],{before:true,after:true});
  result[key].before=false;
  assert.equal(first[key].before,true);
});
