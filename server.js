require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || '';
const ENC_KEY_HEX = process.env.DATA_ENCRYPTION_KEY || '';
const isProd = process.env.NODE_ENV === 'production';
if (JWT_SECRET.length < 32) console.warn('WARNING: set JWT_SECRET to a random secret of at least 32 characters in .env');
if (!/^[a-fA-F0-9]{64}$/.test(ENC_KEY_HEX)) console.warn('WARNING: set DATA_ENCRYPTION_KEY to 64 hex characters in .env; sensitive fields will not be writable until configured.');
const encryptionKey = /^[a-fA-F0-9]{64}$/.test(ENC_KEY_HEX) ? Buffer.from(ENC_KEY_HEX, 'hex') : null;
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const db = new Database(path.join(dataDir, 'natural-oils.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shipments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_id TEXT UNIQUE NOT NULL, order_number TEXT UNIQUE NOT NULL,
 customer_name TEXT NOT NULL, customer_email TEXT, customer_phone_enc TEXT, address_enc TEXT,
 origin TEXT NOT NULL, destination TEXT NOT NULL, contents TEXT NOT NULL DEFAULT 'Goods', quantity INTEGER NOT NULL DEFAULT 1,
 weight_kg REAL NOT NULL DEFAULT 0, declared_value REAL NOT NULL DEFAULT 0, gstin TEXT, payment_status TEXT NOT NULL DEFAULT 'Pending',
 courier_name TEXT NOT NULL DEFAULT 'Natural Oils Logistics', status TEXT NOT NULL DEFAULT 'Order Created',
 expected_delivery TEXT, notes_enc TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by INTEGER,
 FOREIGN KEY(created_by) REFERENCES admins(id)
);
CREATE TABLE IF NOT EXISTS tracking_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, shipment_id INTEGER NOT NULL, status TEXT NOT NULL, location TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '', event_time TEXT NOT NULL, public_visible INTEGER NOT NULL DEFAULT 1,
 FOREIGN KEY(shipment_id) REFERENCES shipments(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS documents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, shipment_id INTEGER NOT NULL, doc_type TEXT NOT NULL, document_number TEXT NOT NULL,
 created_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', FOREIGN KEY(shipment_id) REFERENCES shipments(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, action TEXT NOT NULL, entity_type TEXT NOT NULL,
 entity_id TEXT, ip TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shipments_tracking ON shipments(tracking_id);
CREATE INDEX IF NOT EXISTS idx_shipments_created ON shipments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_shipment ON tracking_events(shipment_id, event_time DESC);
`);

function enc(value) {
  if (value == null || value === '') return null;
  if (!encryptionKey) throw new Error('Server encryption key is not configured. Set DATA_ENCRYPTION_KEY in .env.');
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return `v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${encrypted.toString('base64')}`;
}
function dec(value) {
  if (!value) return '';
  if (!value.startsWith('v1:')) return '';
  if (!encryptionKey) return '';
  try { const [,iv,tag,data] = value.split(':'); const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(iv,'base64')); decipher.setAuthTag(Buffer.from(tag,'base64')); return Buffer.concat([decipher.update(Buffer.from(data,'base64')), decipher.final()]).toString('utf8'); } catch { return ''; }
}
const now = () => new Date().toISOString();
const audit = (req, action, entityType, entityId) => db.prepare('INSERT INTO audit_logs(admin_id,action,entity_type,entity_id,ip,created_at) VALUES(?,?,?,?,?,?)').run(req.admin?.id || null, action, entityType, String(entityId ?? ''), req.ip, now());
function publicShipment(row) {
  return { trackingId: row.tracking_id, orderNumber: row.order_number, destination: row.destination, origin: row.origin,
    contents: row.contents, quantity: row.quantity, weightKg: row.weight_kg, courierName: row.courier_name, status: row.status,
    expectedDelivery: row.expected_delivery, createdAt: row.created_at, updatedAt: row.updated_at,
    events: db.prepare('SELECT status,location,description,event_time AS eventTime FROM tracking_events WHERE shipment_id=? AND public_visible=1 ORDER BY event_time DESC').all(row.id) };
}
function adminShipment(row) {
  return { ...publicShipment(row), id: row.id, customerName: row.customer_name, customerEmail: row.customer_email || '', customerPhone: dec(row.customer_phone_enc), address: dec(row.address_enc), declaredValue: row.declared_value, gstin: row.gstin || '', paymentStatus: row.payment_status, notes: dec(row.notes_enc), createdBy: row.created_by };
}
function auth(req,res,next) {
  const token = req.cookies.no_admin;
  if (!token) return res.status(401).json({error:'Please log in.'});
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); } catch { res.clearCookie('no_admin'); return res.status(401).json({error:'Session expired. Please log in again.'}); }
}
function cleanText(v, max=500) { return String(v ?? '').trim().slice(0,max); }
function makeId(prefix) { return prefix + '-' + crypto.randomBytes(4).toString('hex').toUpperCase(); }
function required(v, label) { const s=cleanText(v,500); if(!s) throw new Error(`${label} is required.`); return s; }

app.disable('x-powered-by');
app.set('trust proxy', isProd ? 1 : false);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'","'unsafe-inline'",'https://fonts.googleapis.com'], fontSrc:["'self'",'https://fonts.gstatic.com'], imgSrc:["'self'","data:"], connectSrc:["'self'"], objectSrc:["'none'"], upgradeInsecureRequests: isProd ? [] : null } }}));
app.use(express.json({limit:'200kb'})); app.use(cookieParser());
app.use('/api/', rateLimit({windowMs:15*60*1000,limit:300,standardHeaders:true,legacyHeaders:false}));
app.use('/api/auth/login', rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false,message:{error:'Too many login attempts. Please wait and try again.'}}));
app.use(express.static(path.join(__dirname,'public'), { etag:true, maxAge: isProd ? '1h' : 0 }));

const adminCount = db.prepare('SELECT COUNT(*) AS n FROM admins').get().n;
if (adminCount === 0 && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && JWT_SECRET.length >= 32) {
  db.prepare('INSERT INTO admins(email,password_hash,created_at) VALUES(?,?,?)').run(process.env.ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12), now());
  console.log(`Initial admin created: ${process.env.ADMIN_EMAIL}. Change the password after first login.`);
}

app.get('/api/health', (_req,res)=>res.json({ok:true,service:'Natural Oils Courier Portal',time:now()}));
app.post('/api/auth/login', async (req,res)=>{
  const email=cleanText(req.body.email,254).toLowerCase(), password=String(req.body.password||'');
  const admin=db.prepare('SELECT * FROM admins WHERE email=?').get(email);
  if(!admin || !(await bcrypt.compare(password,admin.password_hash))) return res.status(401).json({error:'Invalid email or password.'});
  if(JWT_SECRET.length<32) return res.status(500).json({error:'Server authentication secret is not configured securely.'});
  const token=jwt.sign({id:admin.id,email:admin.email},JWT_SECRET,{expiresIn:'8h'});
  res.cookie('no_admin',token,{httpOnly:true,secure:isProd,sameSite:'strict',maxAge:8*60*60*1000,path:'/'});
  audit({admin,ip:req.ip},'LOGIN','admin',admin.id); res.json({ok:true,email:admin.email});
});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie('no_admin',{httpOnly:true,secure:isProd,sameSite:'strict',path:'/'});res.json({ok:true});});
app.get('/api/auth/me',auth,(req,res)=>res.json({id:req.admin.id,email:req.admin.email}));

app.get('/api/track/:trackingId',(req,res)=>{
  const id=cleanText(req.params.trackingId,80).toUpperCase();
  const row=db.prepare('SELECT * FROM shipments WHERE upper(tracking_id)=? OR upper(order_number)=?').get(id,id);
  if(!row) return res.status(404).json({error:'No shipment found. Check the tracking ID and try again.'});
  res.json(publicShipment(row));
});
app.get('/api/admin/summary',auth,(req,res)=>{
  const total=db.prepare('SELECT COUNT(*) n FROM shipments').get().n;
  const inTransit=db.prepare("SELECT COUNT(*) n FROM shipments WHERE status IN ('Picked Up','In Transit','Out for Delivery','Arrived at Hub')").get().n;
  const delivered=db.prepare("SELECT COUNT(*) n FROM shipments WHERE status='Delivered'").get().n;
  const pending=db.prepare("SELECT COUNT(*) n FROM shipments WHERE status IN ('Order Created','Pending Pickup')").get().n;
  const recent=db.prepare('SELECT * FROM shipments ORDER BY id DESC LIMIT 8').all().map(adminShipment);
  res.json({total,inTransit,delivered,pending,recent});
});
app.get('/api/admin/shipments',auth,(req,res)=>{
  const q=cleanText(req.query.q,100); const status=cleanText(req.query.status,80);
  let rows;
  if(q && status) rows=db.prepare('SELECT * FROM shipments WHERE (tracking_id LIKE ? OR order_number LIKE ? OR customer_name LIKE ? OR destination LIKE ?) AND status=? ORDER BY id DESC LIMIT 300').all(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,status);
  else if(q) rows=db.prepare('SELECT * FROM shipments WHERE tracking_id LIKE ? OR order_number LIKE ? OR customer_name LIKE ? OR destination LIKE ? ORDER BY id DESC LIMIT 300').all(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`);
  else if(status) rows=db.prepare('SELECT * FROM shipments WHERE status=? ORDER BY id DESC LIMIT 300').all(status);
  else rows=db.prepare('SELECT * FROM shipments ORDER BY id DESC LIMIT 300').all();
  res.json(rows.map(adminShipment));
});
const allowedStatuses=['Order Created','Pending Pickup','Picked Up','In Transit','Arrived at Hub','Out for Delivery','Delivered','Delivery Attempted','On Hold','Returned to Sender','Cancelled'];
function validateShipment(b) {
  const status=allowedStatuses.includes(b.status)?b.status:'Order Created';
  const quantity=Math.max(1,Math.min(100000,Number.parseInt(b.quantity,10)||1));
  const weight=Math.max(0,Math.min(100000,Number(b.weightKg)||0));
  const value=Math.max(0,Math.min(1e9,Number(b.declaredValue)||0));
  return {tracking_id:cleanText(b.trackingId,80).toUpperCase()||makeId('NO'),order_number:cleanText(b.orderNumber,80).toUpperCase()||makeId('ORD'),customer_name:required(b.customerName,'Customer name'),customer_email:cleanText(b.customerEmail,254),customer_phone_enc:enc(cleanText(b.customerPhone,40)),address_enc:enc(cleanText(b.address,1200)),origin:required(b.origin,'Origin'),destination:required(b.destination,'Destination'),contents:cleanText(b.contents,300)||'Goods',quantity,weight_kg:weight,declared_value:value,gstin:cleanText(b.gstin,20).toUpperCase(),payment_status:['Pending','Paid','COD','Refunded'].includes(b.paymentStatus)?b.paymentStatus:'Pending',courier_name:cleanText(b.courierName,100)||'Natural Oils Logistics',status,expected_delivery:cleanText(b.expectedDelivery,30),notes_enc:enc(cleanText(b.notes,2000))};
}
app.post('/api/admin/shipments',auth,(req,res)=>{
 try {
  const s=validateShipment(req.body); const t=now();
  const result=db.prepare(`INSERT INTO shipments(tracking_id,order_number,customer_name,customer_email,customer_phone_enc,address_enc,origin,destination,contents,quantity,weight_kg,declared_value,gstin,payment_status,courier_name,status,expected_delivery,notes_enc,created_at,updated_at,created_by) VALUES(@tracking_id,@order_number,@customer_name,@customer_email,@customer_phone_enc,@address_enc,@origin,@destination,@contents,@quantity,@weight_kg,@declared_value,@gstin,@payment_status,@courier_name,@status,@expected_delivery,@notes_enc,@created_at,@updated_at,@created_by)`).run({...s,created_at:t,updated_at:t,created_by:req.admin.id});
  db.prepare('INSERT INTO tracking_events(shipment_id,status,location,description,event_time,public_visible) VALUES(?,?,?,?,?,1)').run(result.lastInsertRowid,s.status,s.origin,'Shipment record created.',t);
  audit(req,'CREATE','shipment',result.lastInsertRowid); res.status(201).json(adminShipment(db.prepare('SELECT * FROM shipments WHERE id=?').get(result.lastInsertRowid)));
 } catch(e){res.status(e.message.includes('UNIQUE')?409:400).json({error:e.message.includes('UNIQUE')?'Tracking ID or order number already exists.':e.message});}
});
app.put('/api/admin/shipments/:id',auth,(req,res)=>{
 try {
  const id=Number(req.params.id), existing=db.prepare('SELECT * FROM shipments WHERE id=?').get(id); if(!existing)return res.status(404).json({error:'Shipment not found.'});
  const s=validateShipment({...req.body,trackingId:req.body.trackingId||existing.tracking_id,orderNumber:req.body.orderNumber||existing.order_number});
  const t=now(); db.prepare(`UPDATE shipments SET tracking_id=@tracking_id,order_number=@order_number,customer_name=@customer_name,customer_email=@customer_email,customer_phone_enc=@customer_phone_enc,address_enc=@address_enc,origin=@origin,destination=@destination,contents=@contents,quantity=@quantity,weight_kg=@weight_kg,declared_value=@declared_value,gstin=@gstin,payment_status=@payment_status,courier_name=@courier_name,status=@status,expected_delivery=@expected_delivery,notes_enc=@notes_enc,updated_at=@updated_at WHERE id=@id`).run({...s,updated_at:t,id});
  if(s.status!==existing.status) db.prepare('INSERT INTO tracking_events(shipment_id,status,location,description,event_time,public_visible) VALUES(?,?,?,?,?,1)').run(id,s.status,s.destination,`Status updated to ${s.status}.`,t);
  audit(req,'UPDATE','shipment',id); res.json(adminShipment(db.prepare('SELECT * FROM shipments WHERE id=?').get(id)));
 } catch(e){res.status(e.message.includes('UNIQUE')?409:400).json({error:e.message.includes('UNIQUE')?'Tracking ID or order number already exists.':e.message});}
});
app.post('/api/admin/shipments/:id/events',auth,(req,res)=>{
 const id=Number(req.params.id), row=db.prepare('SELECT * FROM shipments WHERE id=?').get(id); if(!row)return res.status(404).json({error:'Shipment not found.'});
 const status=cleanText(req.body.status,80); if(!allowedStatuses.includes(status))return res.status(400).json({error:'Choose a valid shipment status.'});
 const t=cleanText(req.body.eventTime,40)||now(); const location=cleanText(req.body.location,200); const description=cleanText(req.body.description,500); const visible=req.body.publicVisible===false?0:1;
 const run=db.transaction(()=>{db.prepare('INSERT INTO tracking_events(shipment_id,status,location,description,event_time,public_visible) VALUES(?,?,?,?,?,?)').run(id,status,location,description,t,visible);db.prepare('UPDATE shipments SET status=?,updated_at=? WHERE id=?').run(status,now(),id);});
 run(); audit(req,'ADD_TRACKING_EVENT','shipment',id); res.json({ok:true});
});
app.get('/api/admin/audit',auth,(req,res)=>res.json(db.prepare('SELECT id,admin_id,action,entity_type,entity_id,ip,created_at FROM audit_logs ORDER BY id DESC LIMIT 150').all()));

function createPdf(res, title, subtitle, lines, filename) {
 const doc=new PDFDocument({size:'A4',margin:48,info:{Title:title,Author:'Natural Oils'}});
 res.setHeader('Content-Type','application/pdf'); res.setHeader('Content-Disposition',`attachment; filename="${filename}"`); doc.pipe(res);
 doc.fontSize(23).fillColor('#123b66').text('NATURAL OILS'); doc.moveDown(.25); doc.fontSize(17).fillColor('#1f2937').text(title); doc.fontSize(9).fillColor('#6b7280').text(subtitle); doc.moveDown();
 doc.strokeColor('#dbe3ed').moveTo(48,doc.y).lineTo(547,doc.y).stroke(); doc.moveDown();
 lines.forEach(([k,v])=>{doc.fontSize(10).fillColor('#64748b').text(k.toUpperCase(),{continued:true});doc.fillColor('#111827').text(`  ${String(v??'Not provided')}`);doc.moveDown(.45);});
 doc.moveDown();doc.fontSize(9).fillColor('#6b7280').text('This document is generated by Natural Oils. Verify all details before use.'); doc.end();
}
app.get('/api/admin/shipments/:id/document/:type',auth,(req,res)=>{
 const id=Number(req.params.id), type=cleanText(req.params.type,30); const row=db.prepare('SELECT * FROM shipments WHERE id=?').get(id); if(!row)return res.status(404).json({error:'Shipment not found.'});
 if(!['receipt','consignment','invoice','ewaybill-draft'].includes(type))return res.status(400).json({error:'Unsupported document type.'});
 const docNumber=makeId(type==='receipt'?'NOR':type==='invoice'?'INV':type==='ewaybill-draft'?'EWB-DRAFT':'CN');
 db.prepare('INSERT INTO documents(shipment_id,doc_type,document_number,created_at,metadata_json) VALUES(?,?,?,?,?)').run(id,type,docNumber,now(),JSON.stringify({official:false})); audit(req,'GENERATE_DOCUMENT',type,id);
 const title={receipt:'Order Receipt',consignment:'Consignment Note',invoice:'Tax Invoice Draft', 'ewaybill-draft':'E-Way Bill Data Draft (Not Official)'}[type];
 const lines=[['Document number',docNumber],['Order number',row.order_number],['Tracking ID',row.tracking_id],['Customer',row.customer_name],['Customer email',row.customer_email],['Customer phone',dec(row.customer_phone_enc)],['Delivery address',dec(row.address_enc)],['Origin',row.origin],['Destination',row.destination],['Contents',row.contents],['Quantity',row.quantity],['Weight (kg)',row.weight_kg],['Declared value (INR)',`₹${Number(row.declared_value).toFixed(2)}`],['GSTIN',row.gstin||'Not provided'],['Payment status',row.payment_status],['Shipment status',row.status],['Expected delivery',row.expected_delivery||'Not provided']];
 if(type==='ewaybill-draft') lines.push(['Legal notice','This is an internal data draft only. It is NOT an official government E-Way Bill and has no government EWB number. Generate/validate the official E-Way Bill through the authorised GST portal or an approved integration, where legally required.']);
 createPdf(res,title,`Generated ${new Date().toLocaleString('en-IN')} | ${type==='ewaybill-draft'?'INTERNAL DRAFT, NOT A GOVERNMENT DOCUMENT':'Internal business document'}`,lines,`${docNumber}.pdf`);
});
app.get('/api/admin/export.csv',auth,(req,res)=>{
 const rows=db.prepare('SELECT * FROM shipments ORDER BY id DESC').all(); const cols=['tracking_id','order_number','customer_name','customer_email','origin','destination','contents','quantity','weight_kg','declared_value','gstin','payment_status','courier_name','status','expected_delivery','created_at','updated_at'];
 const csv=[cols.join(','),...rows.map(r=>cols.map(k=>'"'+String(r[k]??'').replace(/"/g,'""')+'"').join(','))].join('\r\n'); audit(req,'EXPORT','shipments','all'); res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition','attachment; filename="natural-oils-shipments.csv"');res.send('\uFEFF'+csv);
});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'An unexpected server error occurred.'});});
app.listen(PORT,()=>console.log(`Natural Oils portal running on http://localhost:${PORT}`));
