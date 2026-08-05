#!/usr/bin/env node
/**
 * create-mongo-user.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Creates MongoDB Atlas user: div / dive123091
 *
 * Prerequisites:
 *   - Get your Atlas Public/Private API keys from:
 *     https://cloud.mongodb.com → Access Manager → API Keys
 *   - Get your Project ID from Atlas URL or API
 *
 * Usage:
 *   ATLAS_PUBLIC_KEY=xxx ATLAS_PRIVATE_KEY=yyy ATLAS_PROJECT_ID=zzz node create-mongo-user.js
 */

const https = require('https');

const PUBLIC_KEY  = process.env.ATLAS_PUBLIC_KEY;
const PRIVATE_KEY = process.env.ATLAS_PRIVATE_KEY;
const PROJECT_ID  = process.env.ATLAS_PROJECT_ID;

if (!PUBLIC_KEY || !PRIVATE_KEY || !PROJECT_ID) {
  console.error('\n❌  Missing environment variables!');
  console.error('   Set: ATLAS_PUBLIC_KEY, ATLAS_PRIVATE_KEY, ATLAS_PROJECT_ID\n');
  console.error('   Get API keys from: https://cloud.mongodb.com → Access Manager → API Keys');
  console.error('   Get Project ID from your Atlas project URL.\n');
  console.error('   Run:');
  console.error('   ATLAS_PUBLIC_KEY=xxx ATLAS_PRIVATE_KEY=yyy ATLAS_PROJECT_ID=zzz node create-mongo-user.js\n');
  process.exit(1);
}

// Digest auth helper
function md5(str){
  const { createHash } = require('crypto');
  return createHash('md5').update(str).digest('hex');
}

function digestRequest(options, body, publicKey, privateKey, cb){
  // First request to get the nonce
  const req = https.request(options, res=>{
    if(res.statusCode !== 401){
      let data='';
      res.on('data',c=>data+=c);
      res.on('end',()=>cb(null,{status:res.statusCode,body:data}));
      return;
    }
    const wwwAuth = res.headers['www-authenticate']||'';
    const realm   = (wwwAuth.match(/realm="([^"]+)"/)   ||[])[1]||'';
    const nonce   = (wwwAuth.match(/nonce="([^"]+)"/)   ||[])[1]||'';
    const qop     = (wwwAuth.match(/qop="([^"]+)"/)     ||[])[1]||'auth';
    const nc      = '00000001';
    const cnonce  = Math.random().toString(36).slice(2);
    const ha1     = md5(`${publicKey}:${realm}:${privateKey}`);
    const ha2     = md5(`${options.method}:${options.path}`);
    const response= md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
    const authHeader = `Digest username="${publicKey}",realm="${realm}",nonce="${nonce}",uri="${options.path}",qop=${qop},nc=${nc},cnonce="${cnonce}",response="${response}"`;
    options.headers['Authorization'] = authHeader;
    const req2 = https.request(options, res2=>{
      let data='';
      res2.on('data',c=>data+=c);
      res2.on('end',()=>cb(null,{status:res2.statusCode,body:data}));
    });
    req2.on('error',cb);
    if(body) req2.write(body);
    req2.end();
  });
  req.on('error',cb);
  if(body) req.write(body);
  req.end();
}

const payload = JSON.stringify({
  databaseName: 'admin',
  groupId: PROJECT_ID,
  roles: [
    { databaseName: 'div_db', roleName: 'readWrite' }
  ],
  username: 'div',
  password: 'dive123091'
});

const options = {
  hostname: 'cloud.mongodb.com',
  path:     `/api/atlas/v1.0/groups/${PROJECT_ID}/databaseUsers`,
  method:   'POST',
  headers:  {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(payload)
  }
};

console.log('\n🔧 Creating MongoDB Atlas user: div');
console.log('   Database: div_db');
console.log('   Project:  ' + PROJECT_ID + '\n');

digestRequest(options, payload, PUBLIC_KEY, PRIVATE_KEY, (err, res)=>{
  if(err){ console.error('❌ Request error:', err.message); process.exit(1); }
  let parsed;
  try{ parsed = JSON.parse(res.body); } catch(e){ parsed = res.body; }
  if(res.status===201){
    console.log('✅ User "div" created successfully!');
    console.log('   Username: div');
    console.log('   Password: dive123091');
    console.log('   Database: div_db\n');
    console.log('📋 .env file is already configured. Run:');
    console.log('   cd /home/harsh/Downloads/dk/div');
    console.log('   npm install && npm start\n');
  } else if(res.status===409){
    console.log('⚠️  User "div" already exists in this project.');
    console.log('   If the password is different, update it in the Atlas dashboard.');
    console.log('   https://cloud.mongodb.com → Database Access\n');
  } else {
    console.error('❌ Failed (HTTP '+res.status+'):');
    console.error(JSON.stringify(parsed, null, 2));
    console.error('\n💡 Alternatively, create the user manually:');
    console.error('   https://cloud.mongodb.com → Database Access → + Add New Database User');
    console.error('   Username: div | Password: dive123091 | Role: readWrite on div_db\n');
    process.exit(1);
  }
});
